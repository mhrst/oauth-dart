import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:googleapis_auth/auth_io.dart';
import 'package:http/http.dart' as http;

enum GoogleOAuthConsentMode {
  standard,
  offlinePkce,
}

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
    required this.tokenPath,
    required this.reason,
    required this.consentDescription,
  });

  final String tokenPath;
  final String reason;
  final String consentDescription;

  String get message => '$reason Google OAuth reauthorization is required for '
      '$consentDescription. Refresh the cached token at $tokenPath, then retry.';

  @override
  String toString() => message;
}

final class GoogleOAuthClientFactory {
  GoogleOAuthClientFactory({
    required this.clientId,
    required this.tokenStoreFile,
    this.allowUserConsent = true,
    this.forceConsent = false,
    this.listenPort = 0,
    this.hostedDomain,
    this.consentMode = GoogleOAuthConsentMode.standard,
    this.customPostAuthPage,
    this.tokenLabel = 'Google OAuth token',
    this.consentDescription = 'Google API access',
    this.autoOpenBrowser = false,
    this.onMessage,
    this.httpClientFactory,
    this.refreshGracePeriod = const Duration(minutes: 5),
  });

  final GoogleOAuthClientId clientId;
  final File tokenStoreFile;
  final bool allowUserConsent;
  final bool forceConsent;
  final int listenPort;
  final String? hostedDomain;
  final GoogleOAuthConsentMode consentMode;
  final String? customPostAuthPage;
  final String tokenLabel;
  final String consentDescription;
  final bool autoOpenBrowser;
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
    final googleClientId = clientId.toClientId();
    var reauthorizationReason =
        'No cached $tokenLabel was found at ${tokenStoreFile.path}.';

    if (!forceConsent) {
      final cachedCredentials = await readCachedCredentials(tokenStoreFile);
      if (cachedCredentials != null) {
        reauthorizationReason =
            'The cached $tokenLabel at ${tokenStoreFile.path} is incomplete.';

        if (cachedCredentials.refreshToken != null) {
          if (coversScopes(cachedCredentials.scopes, scopes)) {
            final cachedClient = await _createClientFromCachedCredentials(
              clientId: googleClientId,
              cachedCredentials: cachedCredentials,
            );
            if (cachedClient != null) {
              _writeMessage('Using cached $tokenLabel ${tokenStoreFile.path}.');
              return cachedClient;
            }
            reauthorizationReason =
                'The cached $tokenLabel at ${tokenStoreFile.path} expired or was revoked.';
          } else {
            reauthorizationReason =
                'The cached $tokenLabel at ${tokenStoreFile.path} does not '
                'cover the requested scopes.';
            _writeMessage(
              'Cached $tokenLabel does not cover the requested scopes; '
              'requesting consent again.',
            );
          }
        }
      }
    }

    if (!allowUserConsent) {
      throw GoogleOAuthAuthorizationRequiredException(
        tokenPath: tokenStoreFile.path,
        reason: reauthorizationReason,
        consentDescription: consentDescription,
      );
    }

    return _createClientViaUserConsent(
      clientId: googleClientId,
      scopes: scopes,
    );
  }

  Future<ManagedAuthClient?> _createClientFromCachedCredentials({
    required ClientId clientId,
    required AccessCredentials cachedCredentials,
  }) async {
    final baseClient = _createHttpClient();
    try {
      final shouldRefresh = _shouldRefreshCachedCredentials(cachedCredentials);
      final initialCredentials = shouldRefresh
          ? await refreshCredentials(clientId, cachedCredentials, baseClient)
          : cachedCredentials;

      if (shouldRefresh) {
        await writeCredentials(tokenStoreFile, initialCredentials);
      }

      final client = autoRefreshingClient(
        clientId,
        initialCredentials,
        baseClient,
      );
      _listenForCredentialUpdates(client);
      return ManagedAuthClient(client: client, closeCallback: () {});
    } on ServerRequestFailedException catch (error) {
      baseClient.close();
      if (!isRevokedRefreshTokenError(error)) {
        rethrow;
      }

      await deleteCachedCredentials(tokenStoreFile);
      final message =
          'Cached $tokenLabel at ${tokenStoreFile.path} expired or was revoked.';
      _writeMessage(
        allowUserConsent
            ? '$message Starting a new authorization flow.'
            : '$message Reauthorization is required.',
      );
      return null;
    } catch (_) {
      baseClient.close();
      rethrow;
    }
  }

  Future<ManagedAuthClient> _createClientViaUserConsent({
    required ClientId clientId,
    required List<String> scopes,
  }) async {
    _writeMessage('Requesting Google OAuth consent for $consentDescription.');

    final client = switch (consentMode) {
      GoogleOAuthConsentMode.standard => await _createStandardConsentClient(
          clientId: clientId,
          scopes: scopes,
        ),
      GoogleOAuthConsentMode.offlinePkce => await _createOfflinePkceClient(
          clientId: clientId,
          scopes: scopes,
        ),
    };

    if (client.credentials.refreshToken == null) {
      throw StateError(
        'Google OAuth did not return a refresh token. Revoke the existing '
        'grant for this OAuth client and rerun with forced OAuth consent.',
      );
    }

    await writeCredentials(tokenStoreFile, client.credentials);
    _listenForCredentialUpdates(client);
    return ManagedAuthClient(client: client, closeCallback: () {});
  }

  Future<AutoRefreshingAuthClient> _createStandardConsentClient({
    required ClientId clientId,
    required List<String> scopes,
  }) {
    return clientViaUserConsent(
      clientId,
      scopes,
      (authUrl) {
        _writeMessage(
          'Open this URL in your browser to authorize $consentDescription:',
        );
        _writeMessage(authUrl);
        _writeMessage('Waiting for the OAuth redirect on localhost...');
        _openBrowser(Uri.parse(authUrl));
      },
      hostedDomain: hostedDomain,
      listenPort: listenPort,
      customPostAuthPage: customPostAuthPage,
    );
  }

  Future<AutoRefreshingAuthClient> _createOfflinePkceClient({
    required ClientId clientId,
    required List<String> scopes,
  }) async {
    final baseClient = _createHttpClient();
    try {
      final credentials = await _obtainOfflineAccessCredentials(
        clientId: clientId,
        scopes: scopes,
        baseClient: baseClient,
      );
      return autoRefreshingClient(clientId, credentials, baseClient);
    } catch (_) {
      baseClient.close();
      rethrow;
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
          ..write(customPostAuthPage ?? _defaultPostAuthHtml);
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

  void _listenForCredentialUpdates(AutoRefreshingAuthClient client) {
    client.credentialUpdates.listen((credentials) {
      unawaited(writeCredentials(tokenStoreFile, credentials));
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
        await Process.start(
          'open',
          [uri.toString()],
          mode: ProcessStartMode.detached,
        );
      } on ProcessException catch (error) {
        _writeMessage('Could not open the browser automatically: '
            '${error.message}');
      }
    }());
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

  static Future<AccessCredentials?> readCachedCredentials(File file) async {
    if (!await file.exists()) {
      return null;
    }

    try {
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is! Map) {
        return null;
      }
      return AccessCredentials.fromJson(
        Map<String, dynamic>.from(decoded.cast<String, dynamic>()),
      );
    } catch (_) {
      return null;
    }
  }

  static Future<void> deleteCachedCredentials(File tokenFile) async {
    if (!await tokenFile.exists()) {
      return;
    }

    try {
      await tokenFile.delete();
    } on FileSystemException {
      // A failed cleanup should not block reauthorization.
    }
  }

  static Future<void> writeCredentials(
    File tokenFile,
    AccessCredentials credentials,
  ) async {
    await tokenFile.parent.create(recursive: true);
    const encoder = JsonEncoder.withIndent('  ');
    await tokenFile.writeAsString('${encoder.convert(credentials.toJson())}\n');
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
    const safe = '0123456789-._~'
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
