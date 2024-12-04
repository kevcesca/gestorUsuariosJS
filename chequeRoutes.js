// chequeRoutes.js
import express from 'express';
import { ChequeRepository } from './cheque-repository.js';

const router = express.Router();

// Ruta para obtener los cheques por año y quincena
router.get('/cheques', async (req, res) => {
    const { anio, quincena } = req.query;

    if (!anio || !quincena) {
        return res.status(400).send('El año y la quincena son requeridos');
    }

    try {
        const cheques = await ChequeRepository.getChequesPorAnioYQuincena(anio, quincena);
        res.status(200).json(cheques);
    } catch (error) {
        console.error('Error al obtener los cheques:', error);
        res.status(500).send('Error al obtener los cheques');
    }
});

export default router;
