import express from 'express';
import { CalendarRepository } from './calendar-repository.js';

const router = express.Router();

router.get('/eventos-mes', async (req, res) => {
    const { mes, anio } = req.query;

    if (!mes || !anio) {
        return res.status(400).json({ message: 'El mes y el año son obligatorios.' });
    }

    try {
        const eventos = await CalendarRepository.getEventsByMonth(mes, anio);
        res.status(200).json(eventos);
    } catch (error) {
        console.error('Error al obtener eventos del mes:', error);
        res.status(500).json({ message: 'Error al obtener eventos del mes.' });
    }
});

// Crear un evento
router.post('/evento', async (req, res) => {
    const { fecha, id_empleado, titulo_evento, descripcion } = req.body;

    if (!fecha || !id_empleado || !titulo_evento || !descripcion) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    }

    try {
        // Validar si la fecha existe
        const id_fecha = await CalendarRepository.getFechaId(fecha);

        if (!id_fecha) {
            return res.status(400).json({ message: 'La fecha proporcionada no existe en el calendario.' });
        }

        // Crear el evento
        const nuevoEvento = await CalendarRepository.createEvent({
            id_fecha,
            id_empleado,
            titulo_evento,
            descripcion,
        });

        res.status(201).json({ message: 'Evento creado exitosamente.', evento: nuevoEvento });
    } catch (error) {
        console.error('Error al crear el evento:', error);
        res.status(500).json({ message: 'No se pudo crear el evento.' });
    }
});

export default router;
