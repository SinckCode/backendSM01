require("dotenv").config(); // Cargar variables de entorno
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 5000;

// 📌 Asegurar que `SESSION_SECRET` y `JWT_SECRET` están definidas
if (!process.env.SESSION_SECRET || !process.env.JWT_SECRET) {
    console.error("❌ ERROR: SESSION_SECRET o JWT_SECRET no están definidas en .env");
    process.exit(1);
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
    })
);

// 📌 Conectar a MongoDB
mongoose
    .connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log("✅ Conectado a MongoDB"))
    .catch((err) => console.error("❌ Error al conectar a MongoDB:", err));

// 📌 Modelo de Usuario
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});

const User = mongoose.model("User", UserSchema);

// 📌 Modelo de Mensajes
const MessageSchema = new mongoose.Schema({
    name: String,
    email: String,
    message: String,
    date: { type: Date, default: Date.now },
});

const Message = mongoose.model("Message", MessageSchema);

// 📌 Middleware para verificar autenticación
const authenticateToken = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) return res.status(403).json({ error: "Acceso denegado." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Token inválido." });
        req.user = user;
        next();
    });
};

// 📌 Rutas de autenticación
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ success: "Usuario registrado correctamente." });
    } catch (error) {
        res.status(500).json({ error: "Error al registrar usuario." });
    }
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: "Credenciales incorrectas." });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "2h",
    });
    res.json({ token });
});

// 📌 Rutas para usuarios (Accesibles para cualquier usuario autenticado)
app.get("/users", authenticateToken, async (req, res) => {
    try {
        const users = await User.find().select("-password");
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener los usuarios." });
    }
});

app.delete("/users/:id", authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.status(200).json({ success: "Usuario eliminado correctamente." });
    } catch (error) {
        res.status(500).json({ error: "Error al eliminar usuario." });
    }
});

// 📌 Rutas para mensajes (Accesibles para cualquier usuario autenticado)
app.get("/messages", authenticateToken, async (req, res) => {
    try {
        const messages = await Message.find().sort({ date: -1 });
        return res.status(200).json(messages);
    } catch (error) {
        return res.status(500).json({ error: "Error al obtener los mensajes." });
    }
});

app.post("/messages", async (req, res) => {
    const { name, email, message } = req.body;

    if (!name || !email || !message) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    try {
        const newMessage = new Message({ name, email, message });
        await newMessage.save();
        res.status(201).json({ success: "Mensaje enviado correctamente." });
    } catch (error) {
        res.status(500).json({ error: "Error al enviar el mensaje." });
    }
});

app.delete("/messages/:id", authenticateToken, async (req, res) => {
    try {
        await Message.findByIdAndDelete(req.params.id);
        res.status(200).json({ success: "Mensaje eliminado correctamente." });
    } catch (error) {
        res.status(500).json({ error: "Error al eliminar mensaje." });
    }
});

// 📌 Ruta de configuración del perfil del usuario autenticado
app.put("/settings", authenticateToken, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.findByIdAndUpdate(req.user.id, { email, password: hashedPassword }, { new: true });
        res.status(200).json({ success: "Configuración actualizada correctamente." });
    } catch (error) {
        res.status(500).json({ error: "Error al actualizar configuración." });
    }
});

// 📌 Iniciar servidor
app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
