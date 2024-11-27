import pkg from 'pg';
const { Pool } = pkg;
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { SALT_ROUNDS, PG_HOST, PG_USER, PG_PASSWORD, PG_DATABASE, PG_PORT } from './config.js';

export class CalendarRepository {
  static async getEventsByMonth(mes, anio) {
    const client = await pool.connect();
    try {
      const query = `
        SELECT 
          e.id AS id_evento,
          e.titulo_evento,
          e.descripcion,
          e.fecha_creacion,
          e.estado_evento,
          f.id AS id_fecha,
          f.quincena,
          f.mes,
          f.anio,
          c.fecha,
          c.es_laboral
        FROM 
          eventos e
        JOIN 
          fechas f ON e.id_fecha = f.id
        JOIN 
          calendario c ON f.id_calendario = c.id
        WHERE 
          f.mes = $1 AND 
          f.anio = $2
        ORDER BY 
          c.fecha;
      `;

      const values = [mes, anio];
      const result = await client.query(query, values);

      return result.rows; // Devuelve los eventos como un arreglo
    } catch (error) {
      console.error('Error al obtener eventos del mes:', error);
      throw new Error('Error al obtener eventos del mes.');
    } finally {
      client.release();
    }
  }
}
