import DBLocal from 'db-local'
import bcrypt from 'bcrypt'

import crypto from 'crypto'
import { SALT_ROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
    _id: { type: String, required: true },
    username: { type: String, required: true },
    password: { type: String, required: true }
})

export class UserRepository {
    static async create({ username, password }) {
        Validation.username(username)
        Validation.password(password)

        // Validacion para asegurarse de que el usuario no existe
        const user = User.findOne({ username })
        if (user) {
            throw new Error('El usuario ya existe')
        }

        const id = crypto.randomUUID()

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

        User.create({
            _id: id,
            username,
            password: hashedPassword
        }).save()

        return id
    }

    static async login({ username, password }) {
        Validation.username(username)

        const user = User.findOne({ username })
        if (!user) {
            throw new Error('Usuario no encontrado')
        }

        const isValid = await bcrypt.compare(password, user.password)
        if (!isValid) {
            throw new Error('Contraseña incorrecta')
        }
        const { password: _, ...publicUser } = user

        return publicUser
    }
}

class Validation {
    static username(username) {
        // Validacion de username (Podriamos usar zod)
        if (typeof username !== 'string' || username.length < 3) {
            throw new Error('El nombre de usuario debe ser de 3 caracteres o mas')
        }
    }
    static password(password) {
        if (typeof password !== 'string' || password.length < 6) {
            throw new Error('La contraseña debe ser de 6 caracteres o mas')
        }
    }
}