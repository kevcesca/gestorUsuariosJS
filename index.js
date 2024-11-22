import express from 'express';
import cors from 'cors';
import { PORT, SECRET_JWT_KEY } from './config.js';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { UserRepository } from './user-repository.js';
import bcrypt from 'bcrypt';

const app = express();

app.set('view engine', 'ejs');
app.use(express.json());
app.use(cookieParser());

const allowedOrigins = [
    'http://192.168.100.114:3000', 
    'http://192.168.100.51:3000', 
    'http://localhost:3000',
    'http://192.168.100.219:3000',
    'http://192.168.100.246:3000'

];

app.use(cors({
    origin: (origin, callback) => {
        // Permitir solicitudes sin 'origin' (por ejemplo, herramientas locales como Postman)
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error(`No permitido por CORS: ${origin}`));
        }
    },
    credentials: true, // Permite enviar cookies y encabezados de autenticación
}));

app.get('/', (req, res) => {
    res.render('example', { username: 'devekin' });
});

app.post('/login', async (req, res) => {
    const { correo_usuario, contrasena_usuario } = req.body;

    try {
        // Verifica las credenciales del usuario
        const user = await UserRepository.login({ correo_usuario, contrasena_usuario });

        // Obtén los permisos del usuario basados en sus roles
        const permisos = await UserRepository.getUserPermissions(user.id_empleado);

        // Genera el token JWT incluyendo los permisos
        const token = jwt.sign(
            {
                id: user.id,
                correo_usuario: user.correo_usuario,
                permisos, // Incluye los permisos en el token
            },
            SECRET_JWT_KEY,
            {
                expiresIn: '1h',
            }
        );

        // Configura la cookie httpOnly con el token
        res
            .cookie('access_token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'Strict',
                maxAge: 1000 * 60 * 60, // 1 hora
            })
            .send({ user, token }); // Envía la información del usuario y el token
            console.log('Cookie configurada:', token);
    } catch (error) {
        console.error('Error en el login:', error);
        res.status(401).send(error.message);
    }
});

app.post('/register', async (req, res) => {
    const { nombre_usuario, correo_usuario, contrasena_usuario, rol_id, id_empleado, asigno } = req.body;
    
    try {
        const id = await UserRepository.create({ 
            nombre_usuario, 
            correo_usuario, 
            contrasena_usuario, 
            rol_id, 
            id_empleado,
            asigno
        });
        res.send({ id });
    } catch (error) {
        res.status(400).send(error.message);
    }
});

app.post('/logout', (req, res) => {
    // Elimina la cookie de sesión para cerrar sesión
    res.clearCookie('access_token');
    res.send('logout');
});

app.post('/protected', (req, res) => {
    res.send('protected');
});

// Verificar si el token en la cookie es válido
app.get('/verify-token', async (req, res) => {
    const token = req.cookies.access_token;

    if (!token) {
        return res.status(401).send("No token provided.");
    }

    try {
        // Verifica el token JWT
        const decoded = jwt.verify(token, SECRET_JWT_KEY);

        // Obtener datos adicionales del usuario (nombre_usuario) desde la base de datos
        const client = await pool.connect();
        const result = await client.query(
            'SELECT nombre_usuario FROM usuarios WHERE id = $1',
            [decoded.id]
        );
        client.release();

        if (result.rowCount === 0) {
            return res.status(404).send('Usuario no encontrado');
        }

        const nombre_usuario = result.rows[0].nombre_usuario;

        // Devuelve los datos del usuario
        res.send({
            user: {
                id: decoded.id,
                correo_usuario: decoded.correo_usuario,
                nombre_usuario,
            },
        });
    } catch (error) {
        console.error("Error al verificar el token:", error);
        res.status(401).send("Token inválido.");
    }
});


app.get('/roles-permissions', async (req, res) => {
    try {
        const rolesWithPermissions = await UserRepository.getRolesWithPermissions();
        res.status(200).json(rolesWithPermissions);
    } catch (error) {
        console.error('Error al obtener roles y permisos:', error);
        res.status(500).send('Error al obtener roles y permisos');
    }
});

app.put('/roles/:id', async (req, res) => {
    const { id } = req.params;
    const { nombre_rol, descripcion_rol } = req.body;

    if (!nombre_rol || !descripcion_rol) {
        return res.status(400).send('El nombre y la descripción del rol son obligatorios');
    }

    try {
        const updatedRole = await UserRepository.updateRole({
            rol_id: id,
            nombre_rol,
            descripcion_rol,
        });

        res.status(200).json(updatedRole);
    } catch (error) {
        console.error('Error al actualizar el rol:', error);
        res.status(500).send(error.message);
    }
});

app.get('/roles/:id/permissions', async (req, res) => {
    const { id } = req.params;

    try {
        const permissions = await UserRepository.getRolePermissions(id);
        
        if (permissions.length === 0) {
            return res.status(404).send(`No se encontraron permisos para el rol con ID ${id}`);
        }

        res.status(200).json(permissions);
    } catch (error) {
        console.error('Error al obtener los permisos del rol:', error);
        res.status(500).send('Error al obtener los permisos del rol');
    }
});

app.get('/employee-ids-with-names', async (req, res) => {
    try {
        const employees = await UserRepository.getAllEmployeeIdsWithNames();
        res.status(200).json(employees);
    } catch (error) {
        console.error('Error al obtener IDs y nombres de empleados:', error);
        res.status(500).send('Error al obtener IDs y nombres de empleados');
    }
});


app.get('/permissions', async (req, res) => {
    try {
        const permissions = await UserRepository.getAllPermissions();

        res.status(200).json(permissions);
    } catch (error) {
        console.error('Error al obtener todos los permisos:', error);
        res.status(500).send('Error al obtener todos los permisos');
    }
});

app.get('/verify-permissions', (req, res) => {
    const token = req.cookies.access_token;

    if (!token) {
        return res.status(401).json({ message: 'Token no proporcionado.' });
    }

    try {
        // Verifica el token JWT
        const decoded = jwt.verify(token, SECRET_JWT_KEY);
        console.log('Token recibido en el servidor:', req.cookies.access_token);

        // Aquí puedes agregar lógica adicional si deseas validar permisos
        // desde una base de datos en lugar de confiar solo en el token.

        res.status(200).json({
            id: decoded.id,
            correo_usuario: decoded.correo_usuario,
            permisos: decoded.permisos, // Esto viene del token
        });
    } catch (error) {
        console.error('Error al verificar el token:', error);
        res.status(401).json({ message: 'Token inválido o expirado.' });
    }
});

app.get('/users-with-roles', async (req, res) => {
    try {
        const usersWithRoles = await UserRepository.getUsersWithRoles();
        res.status(200).json(usersWithRoles);
    } catch (error) {
        console.error('Error al obtener usuarios con roles:', error);
        res.status(500).send('Error al obtener usuarios con roles');
    }
});

app.put('/users/:id/toggle-status', async (req, res) => {
    const { id } = req.params;

    try {
        const updatedUser = await UserRepository.toggleUserStatus(id);

        if (!updatedUser) {
            return res.status(404).send('Usuario no encontrado');
        }

        res.status(200).json({
            message: `El estado del usuario con ID ${id} ha sido cambiado correctamente.`,
            estado: updatedUser.estado_usuario,
        });
    } catch (error) {
        console.error('Error al alternar el estado del usuario:', error);
        res.status(500).send('Error al alternar el estado del usuario');
    }
});

app.put('/users/:id/update-details', async (req, res) => {
    const { id } = req.params;
    const { nombre_usuario, correo_usuario } = req.body;

    try {
        if (!nombre_usuario || !correo_usuario) {
            return res.status(400).send('El nombre de usuario y el correo son obligatorios');
        }

        const updatedUser = await UserRepository.updateUserDetails(id, { nombre_usuario, correo_usuario });

        res.status(200).json({
            message: `Los detalles del usuario con ID ${id} se han actualizado correctamente.`,
            usuario: updatedUser,
        });
    } catch (error) {
        console.error('Error al actualizar los detalles del usuario:', error);
        res.status(500).send('Error al actualizar los detalles del usuario');
    }
});

app.post('/users/:id/assign-roles', async (req, res) => {
    const { id } = req.params;
    const { roles } = req.body;

    // Validar que los roles sean un arreglo
    if (!Array.isArray(roles) || roles.length === 0) {
        return res.status(400).send('La lista de roles es inválida o está vacía');
    }

    try {
        // Llamar al método del repositorio para asignar roles
        const result = await UserRepository.assignRolesToUser(id, roles);
        res.status(200).json({
            message: `Roles asignados exitosamente al usuario con ID ${id}`,
            data: result,
        });
    } catch (error) {
        console.error('Error al asignar roles al usuario:', error);
        res.status(500).send('Error al asignar roles al usuario');
    }
});

app.post('/users/:id/change-password', async (req, res) => {
    const { id } = req.params;
    const { newPassword, confirmPassword } = req.body;

    // Validar que las contraseñas coincidan
    if (newPassword !== confirmPassword) {
        return res.status(400).send('Las contraseñas no coinciden.');
    }

    // Validar longitud mínima de la contraseña
    if (!newPassword || newPassword.length < 6) {
        return res.status(400).send('La nueva contraseña debe tener al menos 6 caracteres.');
    }

    try {
        // Actualizar la contraseña (el hashing se hace dentro del repositorio)
        const result = await UserRepository.updatePassword(id, newPassword);

        if (!result) {
            return res.status(404).send('Usuario no encontrado.');
        }

        res.status(200).json({ message: 'Contraseña actualizada exitosamente.' });
    } catch (error) {
        console.error('Error al cambiar la contraseña:', error);
        res.status(500).send('Error al cambiar la contraseña.');
    }
});


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
