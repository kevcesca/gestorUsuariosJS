// cheque-repository.js
import pkg from 'pg';
const { Pool } = pkg;
import { PG_HOST, PG_USER, PG_PASSWORD, PG_DATABASE, PG_PORT } from './config.js';

const pool = new Pool({
    host: PG_HOST,
    user: PG_USER,
    password: PG_PASSWORD,
    database: PG_DATABASE,
    port: PG_PORT,
});

export class ChequeRepository {
    static async getChequesPorAnioYQuincena(anio, quincena) {
        const client = await pool.connect();
        try {
            // Usamos una expresión regular para asegurarnos de que el año y la quincena coincidan
            const regexAnio = `^${anio}`;
            const regexQuincena = `^${quincena}`;
            
            // Query que filtra por el año y la quincena usando regex
            const result = await client.query(
                `SELECT 
                    id_empleado,
                    nombre,
                    tipo_nomina,
                    fecha_cheque,
                    monto,
                    estado_cheque,
                    quincena,
                    fecha,
                    tipo_pago,
                    num_folio
                FROM cheques_generados
                WHERE fecha_cheque::text ~ $1 AND quincena::text ~ $2`, 
                [regexAnio, regexQuincena]
            );

            return result.rows;
        } catch (error) {
            console.error('Error al obtener los cheques:', error);
            throw new Error('No se pudieron obtener los cheques');
        } finally {
            client.release();
        }
    }
}
