import 'dart:io';

import 'package:googleapis_auth/googleapis_auth.dart';
import 'package:oauth_dart/oauth_dart.dart';
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

  group('GoogleOAuthClientFactory', () {
    test('recognizes cached credentials that cover requested scopes', () {
      expect(
        GoogleOAuthClientFactory.coversScopes(
          const ['scope-a', 'scope-b'],
          const ['scope-b'],
        ),
        isTrue,
      );
      expect(
        GoogleOAuthClientFactory.coversScopes(
          const ['scope-a'],
          const ['scope-a', 'scope-b'],
        ),
        isFalse,
      );
    });

    test('reports missing cached token when user consent is disabled',
        () async {
      final tempDir = await Directory.systemTemp.createTemp('oauth_test_');
      addTearDown(() async {
        if (await tempDir.exists()) {
          await tempDir.delete(recursive: true);
        }
      });
      final tokenPath = '${tempDir.path}/missing_token.json';

      final factory = GoogleOAuthClientFactory(
        clientId: const GoogleOAuthClientId(
          identifier: 'client-id',
          secret: 'client-secret',
        ),
        tokenStoreFile: File(tokenPath),
        allowUserConsent: false,
        tokenLabel: 'Test OAuth token',
        consentDescription: 'test access',
      );

      await expectLater(
        () => factory.createManagedClient(scopes: const ['scope-a']),
        throwsA(
          isA<GoogleOAuthAuthorizationRequiredException>()
              .having(
                (error) => error.tokenPath,
                'tokenPath',
                tokenPath,
              )
              .having(
                (error) => error.reason,
                'reason',
                contains('No cached Test OAuth token'),
              ),
        ),
      );
    });

    test('builds an offline consent authorization URI', () {
      final uri = GoogleOAuthClientFactory.authorizationUri(
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
