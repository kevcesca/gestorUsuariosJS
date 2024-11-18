import pkg from 'pg';
const { Pool } = pkg;
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { SALT_ROUNDS, PG_HOST, PG_USER, PG_PASSWORD, PG_DATABASE, PG_PORT } from './config.js';

const pool = new Pool({
    host: PG_HOST,
    user: PG_USER,
    password: PG_PASSWORD,
    database: PG_DATABASE,
    port: PG_PORT,
});

export class UserRepository {
    static async create({ nombre_usuario, correo_usuario, contrasena_usuario, id_empleado, asigno }) {
        Validation.correo_usuario(correo_usuario);
        Validation.contrasena_usuario(contrasena_usuario);

        const client = await pool.connect();

        try {
            // Verificar si el usuario ya existe
            const userExists = await client.query(
                'SELECT * FROM usuarios WHERE id_empleado = $1 OR correo_usuario = $2',
                [id_empleado, correo_usuario]
            );
            if (userExists.rowCount > 0) {
                throw new Error('El id empleado ya está registrado o el correo ya existe');
            }

            const hashedPassword = await bcrypt.hash(contrasena_usuario, SALT_ROUNDS);

            const result = await client.query(
                `INSERT INTO usuarios (id_empleado, nombre_usuario, correo_usuario, contrasena_usuario, asigno, fecha_creacion, estado_usuario)
         VALUES ($1, $2, $3, $4, $5, NOW(), true) RETURNING id`,
                [id_empleado, nombre_usuario, correo_usuario, hashedPassword, asigno]
            );

            return result.rows[0].id;
        } finally {
            client.release();
        }
    }

    static async login({ correo_usuario, contrasena_usuario }) {
        Validation.correo_usuario(correo_usuario);

        const client = await pool.connect();

        try {
            const userResult = await client.query(
                'SELECT * FROM usuarios WHERE correo_usuario = $1',
                [correo_usuario]
            );

            if (userResult.rowCount === 0) {
                throw new Error('Usuario no encontrado');
            }

            const user = userResult.rows[0];
            const isValid = await bcrypt.compare(contrasena_usuario, user.contrasena_usuario);
            if (!isValid) {
                throw new Error('Contraseña incorrecta');
            }

            // Actualizar la fecha de último acceso
            await client.query(
                'UPDATE usuarios SET fecha_ultimo_acceso = NOW() WHERE id = $1',
                [user.id]
            );

            const { contrasena_usuario: _, ...publicUser } = user;
            return publicUser;
        } finally {
            client.release();
        }
    }

    static async getRolesWithPermissions() {
        const client = await pool.connect();
    
        try {
            const query = `
                SELECT 
                    r.rol_id,
                    r.nombre_rol,
                    r.descripcion_rol,
                    array_agg(p.acceso) AS permisos
                FROM 
                    public.roles AS r
                JOIN 
                    public.permisos AS p ON r.rol_id = p.rol_id
                GROUP BY 
                    r.rol_id, 
                    r.nombre_rol, 
                    r.descripcion_rol;
            `;
            const result = await client.query(query);
    
            return result.rows; // Devuelve los roles con permisos como un arreglo de objetos
        } catch (error) {
            console.error('Error al obtener roles con permisos:', error);
            throw new Error('Error al obtener roles con permisos');
        } finally {
            client.release();
        }
    }

    static async updateRole({ rol_id, nombre_rol, descripcion_rol }) {
        const client = await pool.connect();
    
        try {
            const query = `
                UPDATE public.roles
                SET 
                    nombre_rol = $1,
                    descripcion_rol = $2
                WHERE 
                    rol_id = $3
                RETURNING *;
            `;
            const values = [nombre_rol, descripcion_rol, rol_id];
    
            const result = await client.query(query, values);
    
            if (result.rowCount === 0) {
                throw new Error('El rol no existe o no se pudo actualizar');
            }
    
            return result.rows[0]; // Devuelve el rol actualizado
        } catch (error) {
            console.error('Error al actualizar el rol:', error);
            throw new Error('Error al actualizar el rol');
        } finally {
            client.release();
        }
    }

    static async getRolePermissions(rolId) {
        const client = await pool.connect();

        try {
            const query = `
                SELECT 
                    p.permiso_id,
                    p.acceso,
                    r.nombre_rol,
                    r.descripcion_rol
                FROM 
                    permisos AS p
                JOIN 
                    roles AS r ON p.rol_id = r.rol_id
                WHERE 
                    r.rol_id = $1
            `;
            const result = await client.query(query, [rolId]);

            return result.rows; // Devuelve los permisos como un arreglo de objetos
        } catch (error) {
            console.error('Error al obtener los permisos del rol:', error);
            throw new Error('Error al obtener los permisos del rol');
        } finally {
            client.release();
        }
    }

    static async getAllPermissions() {
        const client = await pool.connect();

        try {
            const query = `
                SELECT 
                    permiso_id,
                    acceso
                FROM 
                    permisos
            `;
            const result = await client.query(query);

            return result.rows; // Devuelve todos los permisos como un arreglo de objetos
        } catch (error) {
            console.error('Error al obtener todos los permisos:', error);
            throw new Error('Error al obtener todos los permisos');
        } finally {
            client.release();
        }
    }

    static async getUserPermissions(id_empleado) {
        const client = await pool.connect();

        try {
            const query = `
                SELECT
                    u.id_empleado,
                    u.nombre_usuario,
                    array_agg(DISTINCT p.acceso) AS permisos
                FROM
                    public.usuarios AS u
                JOIN
                    public.usuario_roles AS ur ON u.id = ur.id_usuario
                JOIN
                    public.roles AS r ON ur.id_rol = r.rol_id
                JOIN
                    public.permisos AS p ON r.rol_id = p.rol_id
                WHERE
                    u.id_empleado = $1
                GROUP BY
                    u.id_empleado,
                    u.nombre_usuario;
            `;
            const result = await client.query(query, [id_empleado]);

            if (result.rowCount === 0) {
                throw new Error('No se encontraron permisos para este usuario');
            }

            return result.rows[0].permisos; // Devuelve solo los permisos como un array
        } catch (error) {
            console.error('Error al obtener permisos del usuario:', error);
            throw new Error('Error al obtener permisos del usuario');
        } finally {
            client.release();
        }
    }
}

class Validation {
    static correo_usuario(correo_usuario) {
        if (typeof correo_usuario !== 'string' || correo_usuario.length < 3) {
            throw new Error('El correo debe ser de 3 caracteres o más');
        }
    }
    static contrasena_usuario(contrasena_usuario) {
        if (typeof contrasena_usuario !== 'string' || contrasena_usuario.length < 6) {
            throw new Error('La contraseña debe ser de 6 caracteres o más');
        }
    }
}
