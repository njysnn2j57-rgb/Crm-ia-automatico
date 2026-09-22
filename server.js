require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false }
    : false
});

function signToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      companyId: user.company_id,
      email: user.email
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  try {
    const token = req.cookies.crm_token;

    if (!token) {
      return res.status(401).json({ error: "Não autenticado" });
    }

    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Sessão inválida ou expirada"
    });
  }
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      database: true
    });
  } catch {
    res.status(500).json({
      ok: false,
      database: false
    });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      companyName
    } = req.body;

    if (!name || !email || !password || !companyName) {
      return res.status(400).json({
        error: "Preencha todos os campos"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "A senha precisa ter pelo menos 6 caracteres"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const exists = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (exists.rows.length) {
      return res.status(409).json({
        error: "Este e-mail já está cadastrado"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const companyResult = await client.query(
        "INSERT INTO companies (name) VALUES ($1) RETURNING id, name",
        [companyName.trim()]
      );

      const passwordHash = await bcrypt.hash(password, 12);

      const userResult = await client.query(
        `INSERT INTO users
        (company_id, name, email, password_hash)
        VALUES ($1, $2, $3, $4)
        RETURNING id, company_id, name, email`,
        [
          companyResult.rows[0].id,
          name.trim(),
          normalizedEmail,
          passwordHash
        ]
      );

      await client.query("COMMIT");

      const user = userResult.rows[0];

      res.cookie("crm_token", signToken(user), {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      res.status(201).json({
        user
      });

    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro ao criar conta"
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    const normalizedEmail =
      (email || "").trim().toLowerCase();

    const result = await pool.query(
      `SELECT
        id,
        company_id,
        name,
        email,
        password_hash
       FROM users
       WHERE email = $1`,
      [normalizedEmail]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "E-mail ou senha incorretos"
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password || "",
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "E-mail ou senha incorretos"
      });
    }

    res.cookie("crm_token", signToken(user), {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      user: {
        id: user.id,
        company_id: user.company_id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro ao fazer login"
    });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("crm_token");

  res.json({
    ok: true
  });
});

app.get("/api/me", auth, async (req, res) => {
  const result = await pool.query(
    `SELECT
      id,
      company_id,
      name,
      email
     FROM users
     WHERE id = $1
     AND company_id = $2`,
    [
      req.user.userId,
      req.user.companyId
    ]
  );

  if (!result.rows.length) {
    return res.status(404).json({
      error: "Usuário não encontrado"
    });
  }

  res.json({
    user: result.rows[0]
  });
});

app.get("/api/leads", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
        id,
        name,
        email,
        phone,
        status,
        source,
        notes,
        created_at,
        updated_at
       FROM leads
       WHERE company_id = $1
       ORDER BY created_at DESC`,
      [req.user.companyId]
    );

    res.json({
      leads: result.rows
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro ao buscar leads"
    });
  }
});

app.post("/api/leads", auth, async (req, res) => {
  try {
    const {
      name,
      email,
      phone,
      status,
      source,
      notes
    } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({
        error: "Nome é obrigatório"
      });
    }

    const result = await pool.query(
      `INSERT INTO leads
      (
        company_id,
        name,
        email,
        phone,
        status,
        source,
        notes
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *`,
      [
        req.user.companyId,
        name.trim(),
        email || null,
        phone || null,
        status || "novo",
        source || null,
        notes || null
      ]
    );

    res.status(201).json({
      lead: result.rows[0]
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro ao criar lead"
    });
  }
});

app.patch("/api/leads/:id", auth, async (req, res) => {
  try {
    const {
      name,
      email,
      phone,
      status,
      source,
      notes
    } = req.body;

    const result = await pool.query(
      `UPDATE leads
       SET
         name = COALESCE($1, name),
         email = COALESCE($2, email),
         phone = COALESCE($3, phone),
         status = COALESCE($4, status),
         source = COALESCE($5, source),
         notes = COALESCE($6, notes),
         updated_at = NOW()
       WHERE id = $7
       AND company_id = $8
       RETURNING *`,
      [
        name ?? null,
        email ?? null,
        phone ?? null,
        status ?? null,
        source ?? null,
        notes ?? null,
        req.params.id,
        req.user.companyId
      ]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Lead não encontrado"
      });
    }

    res.json({
      lead: result.rows[0]
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro ao atualizar lead"
    });
  }
});

app.delete("/api/leads/:id", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM leads
       WHERE id = $1
       AND company_id = $2
       RETURNING id`,
      [
        req.params.id,
        req.user.companyId
      ]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Lead não encontrado"
      });
    }

    res.json({
      ok: true
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro ao excluir lead"
    });
  }
});

app.use((req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `CRM IA rodando na porta ${PORT}`
  );
});
