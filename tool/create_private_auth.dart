#!/usr/bin/env dart

import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:oauth_dart/src/google_oauth_client.dart';

const _usageHeader = '''
Creates a Google OAuth private auth file for non-interactive API clients.

Example:
  dart tool/create_private_auth.dart \\
    --client-id client_secret.json \\
    --private-auth .secrets/google_private_auth.json \\
    --scope https://www.googleapis.com/auth/gmail.modify \\
    --scope https://www.googleapis.com/auth/androidpublisher
''';

Future<void> main(List<String> rawArgs) async {
  final parser = _parser();
  try {
    final args = parser.parse(rawArgs);
    if (args.flag('help')) {
      stdout.writeln('$_usageHeader\n${parser.usage}');
      return;
    }

    final clientIdFile = File(_requiredOption(args, 'client-id'));
    final privateAuthFile = File(_requiredOption(args, 'private-auth'));
    final scopes = args.multiOption('scope');
    if (scopes.isEmpty) {
      throw _UsageException('Provide at least one --scope.', parser);
    }

    final clientId = GoogleOAuthClientId.fromJson(
      _readJsonObject(clientIdFile),
    );
    await GoogleOAuthPrivateAuthCreator(
      clientId: clientId,
      privateAuthFile: privateAuthFile,
      listenPort: _nonNegativeInt(args.option('listen-port')!),
      hostedDomain: args.option('hosted-domain'),
      consentDescription: 'Google API access',
      autoOpenBrowser: args.flag('open-browser'),
    ).create(scopes: scopes, force: args.flag('force'));
  } on _UsageException catch (error) {
    stderr.writeln(error.message);
    stderr.writeln('');
    stderr.writeln(error.usage);
    exitCode = 64;
  } on FormatException catch (error) {
    stderr.writeln(error.message);
    if (error.source != null) {
      stderr.writeln(error.source);
    }
    exitCode = 64;
  } on FileSystemException catch (error) {
    stderr.writeln(error.message);
    if (error.path != null) {
      stderr.writeln(error.path);
    }
    exitCode = 2;
  } on StateError catch (error) {
    stderr.writeln(error.message);
    exitCode = 1;
  }
}

ArgParser _parser() {
  return ArgParser()
    ..addOption(
      'client-id',
      help: 'Path to the Google OAuth desktop/web client JSON.',
    )
    ..addOption(
      'private-auth',
      help: 'Path where the generated private auth JSON should be stored.',
    )
    ..addMultiOption(
      'scope',
      help: 'OAuth scope to request. Repeat this option for multiple scopes.',
    )
    ..addOption(
      'listen-port',
      defaultsTo: '0',
      help: 'Localhost callback port for OAuth consent.',
    )
    ..addOption(
      'hosted-domain',
      help: 'Optional Google hosted-domain hint.',
    )
    ..addFlag(
      'open-browser',
      defaultsTo: true,
      help: 'Open the authorization URL in the default browser on macOS.',
    )
    ..addFlag(
      'force',
      negatable: false,
      help: 'Ignore an existing private auth file and request consent again.',
    )
    ..addFlag('help', abbr: 'h', negatable: false);
}

String _requiredOption(ArgResults args, String name) {
  final value = args.option(name);
  if (value != null && value.trim().isNotEmpty) {
    return value;
  }
  throw _UsageException('Missing --$name.', _parser());
}

int _nonNegativeInt(String value) {
  final parsed = int.tryParse(value);
  if (parsed == null || parsed < 0) {
    throw FormatException('Expected a non-negative integer.', value);
  }
  return parsed;
}

Map<String, dynamic> _readJsonObject(File file) {
  final decoded = jsonDecode(file.readAsStringSync());
  if (decoded is Map<String, dynamic>) {
    return decoded;
  }
  throw FormatException('Expected a JSON object.', decoded);
}

final class _UsageException implements Exception {
  _UsageException(this.message, ArgParser parser)
      : usage = '$_usageHeader\n${parser.usage}';

  final String message;
  final String usage;
}
