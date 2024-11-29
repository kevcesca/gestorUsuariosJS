import pkg from 'pg'; // Importamos la librería de PostgreSQL
import {
    PG_USER,
    PG_HOST,
    PG_DATABASE,
    PG_PASSWORD,
    PG_PORT,
} from './config.js'; // Importamos las configuraciones existentes

const { Pool } = pkg;

// Configuración del Pool
export const pool = new Pool({
    user: PG_USER,
    host: PG_HOST,
    database: PG_DATABASE,
    password: PG_PASSWORD,
    port: PG_PORT,
});
