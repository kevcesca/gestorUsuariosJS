import { pool } from './db-config.js'; // Asegúrate de usar la ruta correcta

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

    // Método para crear un evento
    static async createEvent({ id_fecha, id_empleado, titulo_evento, descripcion, estado_evento = 'activo' }) {
        const client = await pool.connect();
        try {
            const query = `
                INSERT INTO eventos (id_fecha, id_empleado, titulo_evento, descripcion, estado_evento, fecha_creacion)
                VALUES ($1, $2, $3, $4, $5, NOW())
                RETURNING *;
            `;
            const values = [id_fecha, id_empleado, titulo_evento, descripcion, estado_evento];
            const result = await client.query(query, values);
    
            return result.rows[0]; // Devuelve el evento creado
        } catch (error) {
            console.error('Error al crear el evento:', error);
            throw new Error('No se pudo crear el evento.');
        } finally {
            client.release();
        }
    }
    

    // Método para buscar o validar la existencia de una fecha
    static async getFechaId(fecha) {
        const client = await pool.connect();
        try {
            // Verificar si la fecha ya existe en fechas
            const queryCheck = `
                SELECT f.id
                FROM fechas f
                JOIN calendario c ON f.id_calendario = c.id
                WHERE c.fecha = $1;
            `;
            const resultCheck = await client.query(queryCheck, [fecha]);
    
            if (resultCheck.rows.length > 0) {
                return resultCheck.rows[0].id; // Devuelve el ID si ya existe
            }
    
            // Insertar en la tabla calendario si la fecha no existe
            const insertCalendario = `
                INSERT INTO calendario (fecha, dia_semana, mes, anio, es_laboral)
                VALUES ($1, TO_CHAR($1::DATE, 'Day'), TO_CHAR($1::DATE, 'Month'), EXTRACT(YEAR FROM $1::DATE), true)
                ON CONFLICT (fecha) DO NOTHING
                RETURNING id;
            `;
            const calendarioResult = await client.query(insertCalendario, [fecha]);
    
            // Obtener el ID de calendario si ya existía
            const id_calendario = calendarioResult.rows[0]?.id || (await client.query(
                `SELECT id FROM calendario WHERE fecha = $1`, [fecha]
            )).rows[0].id;
    
            // Insertar en la tabla fechas
            const insertFechas = `
                INSERT INTO fechas (quincena, mes, anio, id_calendario)
                VALUES (
                    CASE
                        WHEN EXTRACT(DAY FROM $1::DATE) <= 15 THEN 'Primera quincena'
                        ELSE 'Segunda quincena'
                    END,
                    TO_CHAR($1::DATE, 'Month'),
                    EXTRACT(YEAR FROM $1::DATE),
                    $2
                )
                RETURNING id;
            `;
            const fechasResult = await client.query(insertFechas, [fecha, id_calendario]);
    
            return fechasResult.rows[0].id; // Devuelve el ID de la tabla fechas
        } catch (error) {
            console.error('Error al buscar o crear la fecha:', error);
            throw new Error('No se pudo validar o crear la fecha.');
        } finally {
            client.release();
        }
    }    

}
