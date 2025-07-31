import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';

fetch('https://api.ipify.org?format=json')
  .then(res => res.json())
  .then(json => console.log("IP público da Render:", json.ip))
  .catch(err => console.error("Erro ao buscar IP:", err));

const app = express();
app.use(express.json());
app.use(cors({
  origin: 'https://agathadecants.com.br'
}));


async function openDb() {
    return await mysql.createConnection({
        host: 'srv1965.hstgr.io',  // Altere aqui se for usar um banco MySQL na nuvem
        user: 'root',
        password: '@Gui240106',
        database: 'agatha_decants'
    });
}

// Cadastro de usuários
app.post('/cadastrar', async (req, res) => {
    try {
        const { nome, sobrenome, email, senha } = req.body;
        const db = await openDb();

        await db.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome VARCHAR(100),
                sobrenome VARCHAR(100),
                email VARCHAR(150) UNIQUE,
                senha VARCHAR(255)
            )
        `);

        const [existing] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ mensagem: 'E-mail já cadastrado.' });
        }

        const senhaCriptografada = await bcrypt.hash(senha, 10);
        await db.execute('INSERT INTO users (nome, sobrenome, email, senha) VALUES (?, ?, ?, ?)', [
            nome, sobrenome, email, senhaCriptografada
        ]);

        res.status(200).json({ mensagem: 'Usuário cadastrado com sucesso' });
    } catch (erro) {
        console.error('Erro no /cadastrar:', erro);
        res.status(500).json({ erro: 'Erro interno ao cadastrar usuário' });
    }
});

// Login de usuários
app.post('/login', async (req, res) => {
    try {
        const { email, senha } = req.body;
        const db = await openDb();

        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0];

        if (!user) {
            return res.status(401).json({ mensagem: 'E-mail ou senha incorretos' });
        }

        const senhaValida = await bcrypt.compare(senha, user.senha);
        if (!senhaValida) {
            return res.status(401).json({ mensagem: 'E-mail ou senha incorretos' });
        }

        res.status(200).json({ mensagem: 'Login bem-sucedido', nome: user.nome });
    } catch (erro) {
        console.error('Erro no /login:', erro);
        res.status(500).json({ erro: 'Erro interno ao fazer login' });
    }
});

// Listar usuários
app.get('/usuarios', async (req, res) => {
    try {
        const db = await openDb();
        const [users] = await db.execute('SELECT id, nome, sobrenome, email FROM users');
        res.json(users);
    } catch (erro) {
        console.error('Erro no /usuarios:', erro);
        res.status(500).json({ erro: 'Erro interno ao listar usuários' });
    }
});

// Configuração do e-mail
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'agathadecants@gmail.com',
        pass: 'rthz sfjv gzlo guft',
    },
});

// Esqueci a senha
app.post('/esqueci-senha', async (req, res) => {
    try {
        const { email } = req.body;
        const db = await openDb();

        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ mensagem: 'E-mail não encontrado' });
        }

        const token = uuidv4();
        const expiresAt = Date.now() + 1000 * 60 * 15;

        await db.execute(`
            CREATE TABLE IF NOT EXISTS reset_tokens (
                email VARCHAR(150),
                token VARCHAR(100),
                expiresAt BIGINT
            )
        `);

        await db.execute('INSERT INTO reset_tokens (email, token, expiresAt) VALUES (?, ?, ?)', [
            email, token, expiresAt
        ]);

        const link = `https://agathadecants.com.br/TS.html?token=${token}`;

        await transporter.sendMail({
            from: 'agathadecants@gmail.com',
            to: email,
            subject: 'Recuperação de senha - Ágatha Decants',
            html: `<p>Olá,</p><p>Clique no link abaixo para redefinir sua senha:</p><a href="${link}">${link}</a><p>Este link expira em 15 minutos.</p>`
        });

        res.json({ mensagem: 'E-mail de recuperação enviado' });
    } catch (erro) {
        console.error('Erro no /esqueci-senha:', erro);
        res.status(500).json({ erro: 'Erro interno ao enviar e-mail de recuperação' });
    }
});

// Atualizar senha
app.post('/update-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        const db = await openDb();

        const [tokens] = await db.execute('SELECT * FROM reset_tokens WHERE token = ?', [token]);
        const tokenData = tokens[0];

        if (!tokenData) {
            return res.status(400).json({ mensagem: 'Token inválido' });
        }

        if (Date.now() > tokenData.expiresAt) {
            return res.status(400).json({ mensagem: 'Token expirado' });
        }

        const senhaCriptografada = await bcrypt.hash(newPassword, 10);

        await db.execute('UPDATE users SET senha = ? WHERE email = ?', [senhaCriptografada, tokenData.email]);
        await db.execute('DELETE FROM reset_tokens WHERE token = ?', [token]);

        res.status(200).json({ mensagem: 'Senha atualizada com sucesso' });
    } catch (erro) {
        console.error('Erro no /update-password:', erro);
        res.status(500).json({ erro: 'Erro interno ao atualizar senha' });
    }
});

// ✅ Porta dinâmica para deploy em nuvem
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));


