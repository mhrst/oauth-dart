import 'dart:convert';
import 'dart:io';

import 'package:googleapis_auth/googleapis_auth.dart';
import 'package:oauth_dart/oauth_dart.dart';
import 'package:oauth_dart/src/google_oauth_client.dart'
    show GoogleOAuthPrivateAuthCreator;
import 'package:test/test.dart';

void main() {
  group('GoogleOAuthClientId', () {
    test('parses Google installed-app OAuth client JSON', () {
      final clientId = GoogleOAuthClientId.fromJson({
        'installed': {
          'client_id': 'client-id.apps.googleusercontent.com',
          'client_secret': 'client-secret',
        },
      });

      expect(clientId.identifier, 'client-id.apps.googleusercontent.com');
      expect(clientId.secret, 'client-secret');
    });

    test('parses Google web-app OAuth client JSON', () {
      final clientId = GoogleOAuthClientId.fromJson({
        'web': {
          'client_id': 'client-id.apps.googleusercontent.com',
          'client_secret': 'client-secret',
        },
      });

      expect(clientId.identifier, 'client-id.apps.googleusercontent.com');
      expect(clientId.secret, 'client-secret');
    });

    test('parses direct OAuth client JSON', () {
      final clientId = GoogleOAuthClientId.fromJson({
        'identifier': 'client-id.apps.googleusercontent.com',
        'secret': 'client-secret',
      });

      expect(clientId.identifier, 'client-id.apps.googleusercontent.com');
      expect(clientId.secret, 'client-secret');
    });

    test('rejects OAuth client JSON without a client id', () {
      expect(
        () => GoogleOAuthClientId.fromJson({'installed': <String, Object?>{}}),
        throwsFormatException,
      );
    });
  });

  group('GoogleOAuthPrivateAuth', () {
    test('round trips client id and credentials', () {
      final auth = _oauthToken(
        refreshToken: 'refresh-token',
        scopes: const ['scope-a', 'scope-b'],
      );

      final decoded = GoogleOAuthPrivateAuth.fromJson(auth.toJson());

      expect(decoded.clientId.identifier, 'client-id');
      expect(decoded.clientId.secret, 'client-secret');
      expect(decoded.credentials.refreshToken, 'refresh-token');
      expect(decoded.credentials.scopes, ['scope-a', 'scope-b']);
    });
  });

  group('GoogleOAuthPrivateAuthClientFactory', () {
    test('recognizes credentials that cover requested scopes', () {
      expect(
        GoogleOAuthPrivateAuthClientFactory.coversScopes(
          const ['scope-a', 'scope-b'],
          const ['scope-b'],
        ),
        isTrue,
      );
      expect(
        GoogleOAuthPrivateAuthClientFactory.coversScopes(
          const ['scope-a'],
          const ['scope-a', 'scope-b'],
        ),
        isFalse,
      );
    });

    test('reports missing OAuth token file', () async {
      final tempDir = await Directory.systemTemp.createTemp('oauth_test_');
      addTearDown(() async {
        if (await tempDir.exists()) {
          await tempDir.delete(recursive: true);
        }
      });
      final oauthTokenPath = '${tempDir.path}/missing_auth.json';

      final factory = GoogleOAuthPrivateAuthClientFactory(
        oauthTokenFile: File(oauthTokenPath),
        tokenLabel: 'Test OAuth token file',
        consentDescription: 'test access',
      );

      await expectLater(
        () => factory.createManagedClient(scopes: const ['scope-a']),
        throwsA(
          isA<GoogleOAuthAuthorizationRequiredException>()
              .having(
                (error) => error.oauthTokenPath,
                'oauthTokenPath',
                oauthTokenPath,
              )
              .having(
                (error) => error.reason,
                'reason',
                contains('No Test OAuth token file'),
              ),
        ),
      );
    });

    test('reports OAuth token file without refresh token', () async {
      final tempDir = await Directory.systemTemp.createTemp('oauth_test_');
      addTearDown(() async {
        if (await tempDir.exists()) {
          await tempDir.delete(recursive: true);
        }
      });
      final oauthTokenFile = File('${tempDir.path}/incomplete_auth.json');
      await oauthTokenFile.writeAsString(
        jsonEncode(_oauthToken(refreshToken: null).toJson()),
      );

      final factory = GoogleOAuthPrivateAuthClientFactory(
        oauthTokenFile: oauthTokenFile,
      );

      await expectLater(
        () => factory.createManagedClient(scopes: const ['scope-a']),
        throwsA(
          isA<GoogleOAuthAuthorizationRequiredException>().having(
            (error) => error.reason,
            'reason',
            contains('is incomplete'),
          ),
        ),
      );
    });

    test('reports OAuth token file that does not cover scopes', () async {
      final tempDir = await Directory.systemTemp.createTemp('oauth_test_');
      addTearDown(() async {
        if (await tempDir.exists()) {
          await tempDir.delete(recursive: true);
        }
      });
      final oauthTokenFile = File('${tempDir.path}/scope_auth.json');
      await oauthTokenFile.writeAsString(
        jsonEncode(
          _oauthToken(
            refreshToken: 'refresh-token',
            scopes: const ['scope-a'],
          ).toJson(),
        ),
      );

      final factory = GoogleOAuthPrivateAuthClientFactory(
        oauthTokenFile: oauthTokenFile,
      );

      await expectLater(
        () => factory.createManagedClient(scopes: const ['scope-a', 'scope-b']),
        throwsA(
          isA<GoogleOAuthAuthorizationRequiredException>().having(
            (error) => error.reason,
            'reason',
            contains('does not cover the requested scopes'),
          ),
        ),
      );
    });

    test('builds an offline consent authorization URI', () {
      final uri = GoogleOAuthPrivateAuthCreator.authorizationUri(
        clientId: ClientId('client-id', 'client-secret'),
        scopes: const ['scope-a', 'scope-b'],
        redirectUri: 'http://localhost:1234',
        state: 'state',
        codeVerifier: 'code-verifier',
        hostedDomain: 'example.com',
      );

      expect(uri.scheme, 'https');
      expect(uri.host, 'accounts.google.com');
      expect(uri.path, '/o/oauth2/v2/auth');
      expect(uri.queryParameters, containsPair('access_type', 'offline'));
      expect(uri.queryParameters, containsPair('prompt', 'consent'));
      expect(uri.queryParameters, containsPair('hd', 'example.com'));
      expect(uri.queryParameters, containsPair('scope', 'scope-a scope-b'));
      expect(uri.queryParameters['code_challenge'], isNotEmpty);
    });
  });
}

GoogleOAuthPrivateAuth _oauthToken({
  required String? refreshToken,
  List<String> scopes = const ['scope-a'],
}) {
  return GoogleOAuthPrivateAuth(
    clientId: const GoogleOAuthClientId(
      identifier: 'client-id',
      secret: 'client-secret',
    ),
    credentials: AccessCredentials(
      AccessToken(
        'Bearer',
        'token',
        DateTime.now().toUtc().add(const Duration(hours: 1)),
      ),
      refreshToken,
      scopes,
    ),
  );
}
