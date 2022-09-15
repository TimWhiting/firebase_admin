import 'package:dotenv/dotenv.dart';

final _env = DotEnv(includePlatformEnvironment: true);

final Map<String, String> env = Map.of(_env.map);
