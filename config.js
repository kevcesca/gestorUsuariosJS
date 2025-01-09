// Configuración en config.js
export const {
  PORT = 3001,
  SALT_ROUNDS = 10,
  PG_USER = 'postgres',
  PG_HOST = '192.168.0.58',
  PG_DATABASE = 'SistemaNomina',
  PG_PASSWORD = 'Pjmx3840',
  PG_PORT = 5432,
  SECRET_JWT_KEY = 'superSecretKey-azcapo-impera-jeje1357924680-sistemaNomina'
} = process.env;