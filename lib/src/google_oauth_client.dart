import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:googleapis_auth/auth_io.dart';
import 'package:http/http.dart' as http;

class ManagedAuthClient {
  ManagedAuthClient({
    required this.client,
    required void Function() closeCallback,
  }) : _closeCallback = closeCallback;

  final AutoRefreshingAuthClient client;
  final void Function() _closeCallback;
  var _closed = false;

  void close() {
    if (_closed) {
      return;
    }
    _closed = true;
    client.close();
    _closeCallback();
  }
}

class GoogleOAuthAuthorizationRequiredException implements Exception {
  GoogleOAuthAuthorizationRequiredException({
    required this.privateAuthPath,
    required this.reason,
    required this.consentDescription,
  });

  final String privateAuthPath;
  final String reason;
  final String consentDescription;

  String get message =>
      '$reason Google OAuth reauthorization is required for '
      '$consentDescription. Regenerate the private auth file at '
      '$privateAuthPath, then retry.';

  @override
  String toString() => message;
}

final class GoogleOAuthPrivateAuth {
  const GoogleOAuthPrivateAuth({
    required this.clientId,
    required this.credentials,
  });

  final GoogleOAuthClientId clientId;
  final AccessCredentials credentials;

  factory GoogleOAuthPrivateAuth.fromJson(Map<String, dynamic> json) {
    return GoogleOAuthPrivateAuth(
      clientId: GoogleOAuthClientId.fromJson(_requiredMap(json, 'clientId')),
      credentials: AccessCredentials.fromJson(
        _requiredMap(json, 'credentials'),
      ),
    );
  }

  Map<String, dynamic> toJson() {
    return <String, dynamic>{
      'clientId': clientId.toJson(),
      'credentials': jsonDecode(jsonEncode(credentials.toJson())),
    };
  }

  GoogleOAuthPrivateAuth copyWith({AccessCredentials? credentials}) {
    return GoogleOAuthPrivateAuth(
      clientId: clientId,
      credentials: credentials ?? this.credentials,
    );
  }

  static Map<String, dynamic> _requiredMap(
    Map<String, dynamic> json,
    String key,
  ) {
    final value = json[key];
    if (value is Map) {
      return Map<String, dynamic>.from(value.cast<String, dynamic>());
    }
    throw FormatException('Expected "$key" to be a JSON object.', json);
  }
}

final class GoogleOAuthPrivateAuthClientFactory {
  GoogleOAuthPrivateAuthClientFactory({
    required this.privateAuthFile,
    this.tokenLabel = 'Google OAuth private auth file',
    this.consentDescription = 'Google API access',
    this.onMessage,
    this.httpClientFactory,
    this.refreshGracePeriod = const Duration(minutes: 5),
  });

  final File privateAuthFile;
  final String tokenLabel;
  final String consentDescription;
  final void Function(String message)? onMessage;
  final http.Client Function()? httpClientFactory;
  final Duration refreshGracePeriod;

  Future<AutoRefreshingAuthClient> createClient({
    required List<String> scopes,
  }) async {
    final managedClient = await createManagedClient(scopes: scopes);
    return managedClient.client;
  }

  Future<ManagedAuthClient> createManagedClient({
    required List<String> scopes,
  }) async {
    final privateAuth = await readPrivateAuth(privateAuthFile);
    if (privateAuth == null) {
      throw _authorizationRequired(
        'No $tokenLabel was found at ${privateAuthFile.path}.',
      );
    }

    final credentials = privateAuth.credentials;
    if (credentials.refreshToken == null) {
      throw _authorizationRequired(
        'The $tokenLabel at ${privateAuthFile.path} is incomplete.',
      );
    }

    if (!coversScopes(credentials.scopes, scopes)) {
      throw _authorizationRequired(
        'The $tokenLabel at ${privateAuthFile.path} does not cover the '
        'requested scopes.',
      );
    }

    return _createClientFromPrivateAuth(privateAuth);
  }

  Future<ManagedAuthClient> _createClientFromPrivateAuth(
    GoogleOAuthPrivateAuth privateAuth,
  ) async {
    final clientId = privateAuth.clientId.toClientId();
    final baseClient = _createHttpClient();
    try {
      final shouldRefresh = _shouldRefreshCachedCredentials(
        privateAuth.credentials,
      );
      final initialCredentials = shouldRefresh
          ? await refreshCredentials(
              clientId,
              privateAuth.credentials,
              baseClient,
            )
          : privateAuth.credentials;

      if (shouldRefresh) {
        await writePrivateAuth(
          privateAuthFile,
          privateAuth.copyWith(credentials: initialCredentials),
        );
      }

      final client = autoRefreshingClient(
        clientId,
        initialCredentials,
        baseClient,
      );
      _listenForCredentialUpdates(client, privateAuth);
      _writeMessage('Using $tokenLabel ${privateAuthFile.path}.');
      return ManagedAuthClient(client: client, closeCallback: () {});
    } on ServerRequestFailedException catch (error) {
      baseClient.close();
      if (!isRevokedRefreshTokenError(error)) {
        rethrow;
      }

      _writeMessage(
        '$tokenLabel at ${privateAuthFile.path} expired or was revoked. '
        'Reauthorization is required.',
      );
      throw _authorizationRequired(
        'The $tokenLabel at ${privateAuthFile.path} expired or was revoked.',
      );
    } catch (_) {
      baseClient.close();
      rethrow;
    }
  }

  void _listenForCredentialUpdates(
    AutoRefreshingAuthClient client,
    GoogleOAuthPrivateAuth privateAuth,
  ) {
    client.credentialUpdates.listen((credentials) {
      unawaited(
        writePrivateAuth(
          privateAuthFile,
          privateAuth.copyWith(credentials: credentials),
        ),
      );
    });
  }

  bool _shouldRefreshCachedCredentials(AccessCredentials credentials) {
    final refreshAt = credentials.accessToken.expiry.subtract(
      refreshGracePeriod,
    );
    return DateTime.now().toUtc().isAfter(refreshAt);
  }

  http.Client _createHttpClient() {
    return httpClientFactory == null ? http.Client() : httpClientFactory!();
  }

  GoogleOAuthAuthorizationRequiredException _authorizationRequired(
    String reason,
  ) {
    return GoogleOAuthAuthorizationRequiredException(
      privateAuthPath: privateAuthFile.path,
      reason: reason,
      consentDescription: consentDescription,
    );
  }

  void _writeMessage(String message) {
    if (onMessage != null) {
      onMessage!(message);
      return;
    }
    stdout.writeln(message);
  }

  static bool coversScopes(
    List<String> actualScopes,
    List<String> requiredScopes,
  ) {
    final actual = actualScopes.toSet();
    return requiredScopes.every(actual.contains);
  }

  static bool isRevokedRefreshTokenError(ServerRequestFailedException error) {
    if (error.statusCode != 400) {
      return false;
    }

    final responseContent = error.responseContent;
    if (responseContent is Map) {
      final errorCode = responseContent['error']?.toString().toLowerCase();
      if (errorCode == 'invalid_grant') {
        return true;
      }
    }

    return error.toString().toLowerCase().contains('invalid_grant');
  }

  static Future<GoogleOAuthPrivateAuth?> readPrivateAuth(File file) async {
    if (!await file.exists()) {
      return null;
    }

    try {
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is! Map) {
        return null;
      }
      return GoogleOAuthPrivateAuth.fromJson(
        Map<String, dynamic>.from(decoded.cast<String, dynamic>()),
      );
    } catch (_) {
      return null;
    }
  }

  static Future<void> writePrivateAuth(
    File file,
    GoogleOAuthPrivateAuth privateAuth,
  ) async {
    await file.parent.create(recursive: true);
    const encoder = JsonEncoder.withIndent('  ');
    await file.writeAsString('${encoder.convert(privateAuth.toJson())}\n');
  }
}

final class GoogleOAuthPrivateAuthCreator {
  GoogleOAuthPrivateAuthCreator({
    required this.clientId,
    required this.privateAuthFile,
    this.listenPort = 0,
    this.hostedDomain,
    this.tokenLabel = 'Google OAuth private auth file',
    this.consentDescription = 'Google API access',
    this.autoOpenBrowser = true,
    this.onMessage,
    this.httpClientFactory,
  });

  final GoogleOAuthClientId clientId;
  final File privateAuthFile;
  final int listenPort;
  final String? hostedDomain;
  final String tokenLabel;
  final String consentDescription;
  final bool autoOpenBrowser;
  final void Function(String message)? onMessage;
  final http.Client Function()? httpClientFactory;

  Future<GoogleOAuthPrivateAuth> create({
    required List<String> scopes,
    bool force = false,
  }) async {
    if (!force) {
      final existing =
          await GoogleOAuthPrivateAuthClientFactory.readPrivateAuth(
            privateAuthFile,
          );
      if (existing != null &&
          existing.credentials.refreshToken != null &&
          GoogleOAuthPrivateAuthClientFactory.coversScopes(
            existing.credentials.scopes,
            scopes,
          )) {
        _writeMessage('Using existing $tokenLabel ${privateAuthFile.path}.');
        return existing;
      }
    }

    final baseClient = _createHttpClient();
    try {
      _writeMessage('Requesting Google OAuth consent for $consentDescription.');
      final credentials = await _obtainOfflineAccessCredentials(
        clientId: clientId.toClientId(),
        scopes: scopes,
        baseClient: baseClient,
      );
      if (credentials.refreshToken == null) {
        throw StateError(
          'Google OAuth did not return a refresh token. Revoke the existing '
          'grant for this OAuth client and rerun with --force.',
        );
      }

      final privateAuth = GoogleOAuthPrivateAuth(
        clientId: clientId,
        credentials: credentials,
      );
      await GoogleOAuthPrivateAuthClientFactory.writePrivateAuth(
        privateAuthFile,
        privateAuth,
      );
      _writeMessage('Saved $tokenLabel ${privateAuthFile.path}.');
      return privateAuth;
    } finally {
      baseClient.close();
    }
  }

  Future<AccessCredentials> _obtainOfflineAccessCredentials({
    required ClientId clientId,
    required List<String> scopes,
    required http.Client baseClient,
  }) async {
    final server = await HttpServer.bind('localhost', listenPort);

    try {
      final redirectUri = 'http://localhost:${server.port}';
      final state = _randomState();
      final codeVerifier = _createCodeVerifier();
      final authorizationUrl = authorizationUri(
        clientId: clientId,
        scopes: scopes,
        redirectUri: redirectUri,
        state: state,
        codeVerifier: codeVerifier,
        hostedDomain: hostedDomain,
      );

      _writeMessage('Authorize $consentDescription in your browser:');
      _writeMessage(authorizationUrl.toString());
      _openBrowser(authorizationUrl);

      final request = await server.first;
      try {
        if (request.method != 'GET') {
          throw StateError('Invalid OAuth callback method: ${request.method}.');
        }
        if (request.uri.queryParameters['state'] != state) {
          throw StateError('Invalid OAuth callback state.');
        }
        final error = request.uri.queryParameters['error'];
        if (error != null) {
          throw StateError('Google OAuth failed: $error.');
        }
        final code = request.uri.queryParameters['code'];
        if (code == null || code.isEmpty) {
          throw StateError('Google OAuth callback did not include a code.');
        }

        final credentials = await obtainAccessCredentialsViaCodeExchange(
          baseClient,
          clientId,
          code,
          redirectUrl: redirectUri,
          codeVerifier: codeVerifier,
        );

        request.response
          ..statusCode = 200
          ..headers.set('content-type', 'text/html; charset=UTF-8')
          ..write(_defaultPostAuthHtml);
        await request.response.close();
        return credentials;
      } catch (_) {
        request.response.statusCode = 500;
        await request.response.close().catchError((_) {});
        rethrow;
      }
    } finally {
      await server.close();
    }
  }

  http.Client _createHttpClient() {
    return httpClientFactory == null ? http.Client() : httpClientFactory!();
  }

  void _writeMessage(String message) {
    if (onMessage != null) {
      onMessage!(message);
      return;
    }
    stdout.writeln(message);
  }

  void _openBrowser(Uri uri) {
    if (!autoOpenBrowser || !Platform.isMacOS) {
      return;
    }

    unawaited(() async {
      try {
        await Process.start('open', [
          uri.toString(),
        ], mode: ProcessStartMode.detached);
      } on ProcessException catch (error) {
        _writeMessage(
          'Could not open the browser automatically: '
          '${error.message}',
        );
      }
    }());
  }

  static Uri authorizationUri({
    required ClientId clientId,
    required List<String> scopes,
    required String redirectUri,
    required String state,
    required String codeVerifier,
    String? hostedDomain,
  }) {
    return Uri.https('accounts.google.com', 'o/oauth2/v2/auth', {
      'client_id': clientId.identifier,
      'response_type': 'code',
      'redirect_uri': redirectUri,
      'scope': scopes.join(' '),
      'code_challenge': _codeChallenge(codeVerifier),
      'code_challenge_method': 'S256',
      'access_type': 'offline',
      'prompt': 'consent',
      'state': state,
      if (hostedDomain != null) 'hd': hostedDomain,
    });
  }

  static String _createCodeVerifier() {
    const safe =
        '0123456789-._~'
        'abcdefghijklmnopqrstuvwxyz'
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    final random = Random.secure();
    return List.generate(128, (_) => safe[random.nextInt(safe.length)]).join();
  }

  static String _codeChallenge(String codeVerifier) {
    final digest = sha256.convert(ascii.encode(codeVerifier));
    return _stripBase64Padding(base64UrlEncode(digest.bytes));
  }

  static String _randomState() {
    final random = Random.secure();
    final bytes = Uint8List.fromList([
      for (var i = 0; i < 24; i++) random.nextInt(256),
    ]);
    return _stripBase64Padding(base64UrlEncode(bytes));
  }

  static String _stripBase64Padding(String value) {
    return value.replaceAll(RegExp(r'=+$'), '');
  }
}

final class GoogleOAuthClientId {
  const GoogleOAuthClientId({required this.identifier, this.secret});

  final String identifier;
  final String? secret;

  factory GoogleOAuthClientId.fromJson(Map<String, dynamic> json) {
    final googleConfig = json['installed'] ?? json['web'];
    if (googleConfig is Map<String, dynamic>) {
      return GoogleOAuthClientId(
        identifier: _requiredString(googleConfig, 'client_id'),
        secret: googleConfig['client_secret'] as String?,
      );
    }

    return GoogleOAuthClientId(
      identifier: _requiredString(json, 'identifier'),
      secret: json['secret'] as String?,
    );
  }

  Map<String, dynamic> toJson() {
    return <String, dynamic>{
      'identifier': identifier,
      if (secret != null) 'secret': secret,
    };
  }

  ClientId toClientId() => ClientId(identifier, secret);

  static String _requiredString(Map<String, dynamic> json, String key) {
    final value = json[key];
    if (value is String && value.isNotEmpty) {
      return value;
    }
    throw FormatException('Expected "$key" to be a non-empty string.', json);
  }
}

const String _defaultPostAuthHtml = '''
<!DOCTYPE html>
<html>
  <head><meta charset="utf-8"><title>Authorization successful</title></head>
  <body><h2>Authorization successful. You can close this window.</h2></body>
</html>
''';
