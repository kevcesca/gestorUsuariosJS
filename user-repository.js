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

    // Verifica si la contraseña actual es correcta y no es Azcapotzalco1!
    static async verifyPassword(userId, currentPassword) {
        const client = await pool.connect();

        try {
            // 1. Obtener la contraseña actual encriptada desde la base de datos
            const result = await client.query('SELECT contrasena_usuario FROM usuarios WHERE id_empleado = $1', [userId]);
            if (result.rowCount === 0) {
                throw new Error('Usuario no encontrado');
            }

            const storedHashedPassword = result.rows[0].contrasena_usuario;

            // 2. Verificar si la contraseña actual coincide con la almacenada (usando bcrypt)
            const isPasswordCorrect = await bcrypt.compare(currentPassword, storedHashedPassword);

            if (!isPasswordCorrect) {
                throw new Error('La contraseña actual es incorrecta');
            }

            // 3. Verificar si la contraseña actual es Azcapotzalco1!
            if (currentPassword === 'Azcapotzalco1!') {
                throw new Error('La contraseña no puede ser Azcapotzalco1!');
            }

            return { message: 'Contraseña verificada correctamente' };
        } catch (error) {
            console.error('Error al verificar la contraseña:', error);
            throw new Error(error.message);
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
    
            // Verificar si el usuario está activo
            if (!user.estado_usuario) {
                throw new Error('El usuario está desactivado');
            }
    
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

    static async updatePassword(id_empleado, hashedPassword) {
        const client = await pool.connect();

        try {
            const query = `
                UPDATE usuarios
                SET contrasena_usuario = $1
                WHERE id_empleado = $2
                RETURNING id_empleado;
            `;
            const values = [hashedPassword, id_empleado];

            const result = await client.query(query, values);

            if (result.rowCount === 0) {
                throw new Error('Usuario no encontrado.');
            }

            return result.rows[0]; // Retorna el usuario actualizado
        } catch (error) {
            console.error('Error al actualizar la contraseña:', error);
            throw new Error('Error al actualizar la contraseña.');
        } finally {
            client.release();
        }
    }

    static async findById(id_empleado) {
        const client = await pool.connect();

        try {
            const query = 'SELECT * FROM usuarios WHERE id_empleado = $1';
            const result = await client.query(query, [id_empleado]);

            if (result.rowCount === 0) {
                throw new Error('Usuario no encontrado');
            }

            return result.rows[0];  // Retorna el primer usuario encontrado
        } catch (error) {
            console.error('Error al buscar el usuario por ID:', error);
            throw new Error('Error al buscar el usuario');
        } finally {
            client.release();
        }
    }

    // Modificado para buscar por id_empleado
    static async findByIdEmpleado(id_empleado) {
        const client = await pool.connect();
        try {
            const query = `
            SELECT 
                u.id_empleado,
                u.contrasena_usuario
            FROM 
                usuarios AS u
            WHERE
                u.id_empleado = $1
        `;
            const result = await client.query(query, [id_empleado]);

            // Si no hay ningún usuario con ese id_empleado
            if (result.rows.length === 0) {
                return null;
            }

            return result.rows[0]; // Retorna el primer usuario encontrado
        } catch (error) {
            console.error('Error al buscar el usuario por id_empleado:', error);
            throw new Error('Error al buscar el usuario');
        } finally {
            client.release();
        }
    }

    static async getAllEmployeeIdsWithNames() {
        const client = await pool.connect();

        try {
            const query = `
                SELECT id_empleado, 
                        CONCAT(nombre, ' ', apellido_1, ' ', apellido_2) AS nombre_completo
                FROM empleados;
            `;
            const result = await client.query(query);
            return result.rows; // Devuelve una lista de objetos con id_empleado y nombre_completo
        } catch (error) {
            console.error('Error al obtener IDs y nombres de empleados:', error);
            throw new Error('Error al obtener IDs y nombres de empleados');
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
                    public.roles_permisos AS rp ON r.rol_id = rp.rol_id
                JOIN 
                    public.permisos AS p ON rp.permiso_id = p.permiso_id
                GROUP BY 
                    r.rol_id, r.nombre_rol, r.descripcion_rol;
            `;
            const result = await client.query(query);
            return result.rows; // Devuelve los roles con permisos como un arreglo de objetos
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
                r.rol_id AS "ID del Rol",
                r.nombre_rol AS "Rol",
                r.descripcion_rol AS "Descripción del Rol",
                STRING_AGG(p.acceso, ', ') AS "Permisos"
            FROM 
                public.roles AS r
            INNER JOIN 
                public.roles_permisos AS rp
                ON r.rol_id = rp.rol_id
            INNER JOIN 
                public.permisos AS p
                ON rp.permiso_id = p.permiso_id
            WHERE 
                r.rol_id = $1
            GROUP BY 
                r.rol_id, r.nombre_rol, r.descripcion_rol
            ORDER BY 
                r.rol_id;
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
                    public.roles_permisos AS rp ON r.rol_id = rp.rol_id
                JOIN
                    public.permisos AS p ON rp.permiso_id = p.permiso_id
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
        } finally {
            client.release();
        }
    }

    static async getUsersWithRoles() {
        const client = await pool.connect();
        try {
            const query = `
                SELECT 
                    u.id_empleado AS "ID Empleado",
                    CONCAT(e.nombre, ' ', e.apellido_1, ' ', e.apellido_2) AS "Nombre Empleado",
                    u.nombre_usuario AS "Nombre de Usuario",
                    u.correo_usuario AS "Email",
                    COALESCE(STRING_AGG(DISTINCT r.nombre_rol, ', '), '') AS "Rol",
                    u.fecha_creacion AS "Fecha de Alta",
                    u.asigno AS "Asignó",
                    u.estado_usuario AS "Activo"
                FROM 
                    usuarios AS u
                LEFT JOIN 
                    usuario_roles AS ur
                    ON u.id = ur.id_usuario
                LEFT JOIN 
                    roles AS r
                    ON ur.id_rol = r.rol_id
                LEFT JOIN 
                    empleados AS e
                    ON u.id_empleado = e.id_empleado
                GROUP BY 
                    u.id_empleado, e.nombre, e.apellido_1, e.apellido_2, u.nombre_usuario, u.correo_usuario, u.fecha_creacion, u.asigno, u.estado_usuario
                ORDER BY 
                    u.fecha_creacion DESC; -- Cambiado a descendente para mostrar los más recientes primero
            `;
            const result = await client.query(query);
            return result.rows; // Devuelve los usuarios con roles agrupados
        } catch (error) {
            console.error('Error al obtener usuarios con roles:', error);
            throw new Error('Error al obtener usuarios con roles');
        } finally {
            client.release();
        }
    }    

    static async toggleUserStatus(id_empleado) {
        const client = await pool.connect();

        try {
            const query = `
                UPDATE usuarios
                SET estado_usuario = NOT estado_usuario
                WHERE id_empleado = $1
                RETURNING id_empleado, estado_usuario;
            `;

            const result = await client.query(query, [id_empleado]);

            if (result.rowCount === 0) {
                throw new Error('Usuario no encontrado');
            }

            return result.rows[0]; // Devuelve el usuario con el estado actualizado
        } catch (error) {
            console.error('Error al alternar el estado del usuario:', error);
            throw new Error('Error al alternar el estado del usuario');
        } finally {
            client.release();
        }
    }

    static async updateUserDetails(id_empleado, { nombre_usuario, correo_usuario }) {
        const client = await pool.connect();

        try {
            // Validaciones de los campos
            Validation.correo_usuario(correo_usuario);
            if (!nombre_usuario || typeof nombre_usuario !== 'string') {
                throw new Error('El nombre de usuario es inválido');
            }

            // Actualizar los campos en la base de datos
            const query = `
                UPDATE usuarios
                SET nombre_usuario = $1, correo_usuario = $2
                WHERE id_empleado = $3
                RETURNING id_empleado, nombre_usuario, correo_usuario;
            `;
            const values = [nombre_usuario, correo_usuario, id_empleado];

            const result = await client.query(query, values);

            if (result.rowCount === 0) {
                throw new Error('Usuario no encontrado');
            }

            return result.rows[0]; // Devuelve los datos actualizados
        } catch (error) {
            console.error('Error al actualizar los detalles del usuario:', error);
            throw new Error('Error al actualizar los detalles del usuario');
        } finally {
            client.release();
        }
    }

    static async assignRolesToUser(id_empleado, roles) {
        const client = await pool.connect();
    
        try {
            // Validar que el usuario existe
            const userCheck = await client.query(
                'SELECT id FROM usuarios WHERE id_empleado = $1',
                [id_empleado]
            );
    
            if (userCheck.rowCount === 0) {
                throw new Error('El usuario no existe');
            }
    
            const userId = userCheck.rows[0].id;
    
            // Eliminar todos los roles actuales del usuario
            await client.query('DELETE FROM usuario_roles WHERE id_usuario = $1', [userId]);
    
            // Asignar los nuevos roles
            const insertPromises = roles.map((rolId) =>
                client.query(
                    'INSERT INTO usuario_roles (id_usuario, id_rol) VALUES ($1, $2)',
                    [userId, rolId]
                )
            );
            await Promise.all(insertPromises);
    
            // Obtener los nombres de los roles asignados
            const roleNames = await this.getRoleNamesByIds(roles);
    
            // Devolver el id_empleado, los roles y los nombres de los roles asignados
            return { id_empleado, roles, roleNames };
        } catch (error) {
            console.error('Error al asignar roles al usuario:', error);
            throw new Error('Error al asignar roles al usuario');
        } finally {
            client.release();
        }
    }    

    static async getRoleNamesByIds(roleIds) {
        const client = await pool.connect();
    
        try {
            // Obtener los nombres de los roles por sus IDs (ajustado para usar 'id_rol' en lugar de 'id')
            const query = 'SELECT nombre_rol FROM roles WHERE rol_id = ANY($1)';
            const result = await client.query(query, [roleIds]);
    
            // Extraemos solo los nombres de los roles
            return result.rows.map(row => row.nombre_rol);
        } catch (error) {
            console.error('Error al obtener los nombres de los roles:', error);
            throw new Error('Error al obtener los nombres de los roles');
        } finally {
            client.release();
        }
    }
    

    static async updatePassword(id_empleado, newPassword) {
        const client = await pool.connect();

        try {
            // Hashear la nueva contraseña
            const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

            // Actualizar la contraseña en la base de datos
            const query = `
                UPDATE usuarios
                SET contrasena_usuario = $1
                WHERE id_empleado = $2
                RETURNING id_empleado;
            `;
            const values = [hashedPassword, id_empleado];

            const result = await client.query(query, values);

            if (result.rowCount === 0) {
                throw new Error('Usuario no encontrado.');
            }

            return result.rows[0]; // Retorna el usuario actualizado
        } catch (error) {
            console.error('Error al actualizar la contraseña:', error);
            throw new Error('Error al actualizar la contraseña.');
        } finally {
            client.release();
        }
    }

    static async assignPermissionsToRole(rol_id, permissions) {
        const client = await pool.connect();

        try {
            // Validar que el rol exista
            const roleCheck = await client.query('SELECT * FROM roles WHERE rol_id = $1', [rol_id]);

            if (roleCheck.rowCount === 0) {
                throw new Error('El rol no existe');
            }

            // Eliminar todos los permisos actuales del rol
            await client.query('DELETE FROM roles_permisos WHERE rol_id = $1', [rol_id]);

            // Asignar los nuevos permisos
            const insertPromises = permissions.map((permisoId) =>
                client.query('INSERT INTO roles_permisos (rol_id, permiso_id) VALUES ($1, $2)', [rol_id, permisoId])
            );
            await Promise.all(insertPromises);

            return { rol_id, permissions };
        } catch (error) {
            console.error('Error al asignar permisos al rol:', error);
            throw new Error('Error al asignar permisos al rol');
        } finally {
            client.release();
        }
    }

    static async createRole({ nombre_rol, descripcion_rol, permisos }) {
        const client = await pool.connect();

        try {
            await client.query('BEGIN'); // Iniciar transacción

            // Insertar el nuevo rol
            const roleQuery = `
                INSERT INTO roles (nombre_rol, descripcion_rol)
                VALUES ($1, $2)
                RETURNING rol_id;
            `;
            const roleResult = await client.query(roleQuery, [nombre_rol, descripcion_rol]);
            const newRoleId = roleResult.rows[0].rol_id;

            // Insertar permisos para el rol
            const permissionPromises = permisos.map((permiso_id) =>
                client.query(
                    `
                    INSERT INTO roles_permisos (rol_id, permiso_id)
                    VALUES ($1, $2);
                `,
                    [newRoleId, permiso_id]
                )
            );
            await Promise.all(permissionPromises);

            await client.query('COMMIT'); // Confirmar transacción

            return { rol_id: newRoleId, nombre_rol, descripcion_rol, permisos };
        } catch (error) {
            await client.query('ROLLBACK'); // Revertir cambios en caso de error
            console.error('Error al crear el rol:', error);
            throw new Error('Error al crear el rol');
        } finally {
            client.release();
        }
    }

    static async getEmployeeIdByUserId(userId) {
        try {
            const query = `
                SELECT id_empleado
                FROM public.usuarios
                WHERE id = $1
            `;
            const result = await pool.query(query, [userId]);

            if (result.rows.length === 0) {
                throw new Error('Usuario no encontrado');
            }

            return result.rows[0].id_empleado;
        } catch (error) {
            console.error('Error al obtener el id_empleado:', error);
            throw error;
        }
    }

    static async checkPasswordForEmployee(idEmpleado, password) {
        try {
            // Paso 1: Obtener el hash de la contraseña del empleado desde la base de datos
            const query = `
                SELECT contrasena_usuario
                FROM public.usuarios
                WHERE id_empleado = $1
            `;
            const result = await pool.query(query, [idEmpleado]);

            if (result.rows.length === 0) {
                throw new Error('Empleado no encontrado');
            }

            // Paso 2: Obtener el hash de la contraseña
            const hashedPassword = result.rows[0].contrasena_usuario;

            // Paso 3: Comparar el hash de la contraseña con la contraseña proporcionada
            const match = await bcrypt.compare(password, hashedPassword);

            if (!match) {
                throw new Error('La contraseña es incorrecta');
            }

            return true; // La contraseña es correcta
        } catch (error) {
            console.error('Error al verificar la contraseña del empleado:', error);
            throw error;
        }
    }

    static async deleteRoles(roleIds) {
        const client = await pool.connect();

        try {
            await client.query('BEGIN'); // Inicia una transacción

            // Validar que roleIds sea un arreglo y tenga al menos un elemento
            if (!Array.isArray(roleIds) || roleIds.length === 0) {
                throw new Error('Debe proporcionar al menos un rol para eliminar.');
            }

            // Elimina los permisos asociados con los roles
            await client.query('DELETE FROM roles_permisos WHERE rol_id = ANY($1::int[])', [roleIds]);

            // Elimina los roles
            const result = await client.query('DELETE FROM roles WHERE rol_id = ANY($1::int[]) RETURNING *', [roleIds]);

            await client.query('COMMIT'); // Confirma la transacción

            return result.rows; // Devuelve los roles eliminados
        } catch (error) {
            await client.query('ROLLBACK'); // Revertir la transacción en caso de error
            console.error('Error al eliminar los roles:', error);
            throw new Error('Error al eliminar los roles.');
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
