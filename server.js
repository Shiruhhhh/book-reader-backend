const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3001; // Render usará a variável PORT automaticamente
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

const SECRET = "secret_key"; // Use uma chave mais segura em produção

app.use(bodyParser.json());
app.use(cors());

app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  next();
});

// uploads acessíveis via http://localhost:3001/uploads/
app.use("/uploads", express.static("uploads"));

// Configuração do MySQL
const db = mysql.createConnection({
  host: "localhost",
  user: "root", // Substitua pelo seu usuário do MySQL
  password: "", // Substitua pela sua senha do MySQL
  database: "book_reader", // Nome do banco de dados
});

db.connect((err) => {
  if (err) {
    console.error("Erro ao conectar ao banco de dados:", err);
    return;
  }
  console.log("Conectado ao banco de dados MySQL.");
});

// Rota de Cadastro (Signup)
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  // Verifica se o usuário já existe
  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, result) => {
      if (result.length > 0) {
        return res.status(400).json({ message: "Usuário já existe!" });
      }

      // Criptografa a senha
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insere o usuário no banco
      db.query(
        "INSERT INTO users (name, email, provider, password_hash) VALUES (?, ?, 'email', ?)",
        [name, email, hashedPassword],
        (err) => {
          if (err) {
            return res.status(500).json({ message: "Erro ao criar usuário" });
          }
          res.status(201).json({ message: "Usuário cadastrado com sucesso!" });
        }
      );
    }
  );
});

// Rota de Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, result) => {
      if (result.length === 0) {
        return res.status(404).json({ message: "Usuário não encontrado!" });
      }

      const user = result[0];

      // Verifica a senha
      const isPasswordValid = await bcrypt.compare(
        password,
        user.password_hash
      );
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Senha inválida!" });
      }

      // Gera o token JWT
      const token = jwt.sign({ id: user.id, email: user.email }, SECRET, {
        expiresIn: "1h",
      });

      // Retorna o token e o userId
      res.json({ token, userId: user.id });
    }
  );
});

// Middleware para verificar tokens JWT e Firebase
const admin = require("firebase-admin");
const serviceAccount = require("./my-book-reader-712ee-firebase-adminsdk-mnqmn-3e9b4b488c.json");

// Inicialize o Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Middleware para verificar tokens JWT e Firebase
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ message: "Token ausente!" });
  }

  const token = authHeader.split(" ")[1];
  try {
    // Verificar JWT do sistema
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded; // Adiciona os dados do usuário ao request
    return next();
  } catch (err) {
    try {
      // Verificar token do Firebase
      const decodedToken = await admin.auth().verifyIdToken(token);
      req.user = {
        id: decodedToken.uid,
        email: decodedToken.email,
        provider: decodedToken.firebase.sign_in_provider,
      };
      return next();
    } catch (firebaseErr) {
      return res.status(403).json({ message: "Token inválido!" });
    }
  }
};

app.post("/auth/firebase", async (req, res) => {
  const { token } = req.body;

  if (!token) {
    console.error("Token ausente!");
    return res.status(400).json({ message: "Token ausente!" });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    console.log("Token decodificado com sucesso:", decodedToken);

    const { uid, email, name } = decodedToken;

    // Verificar se o usuário já existe no banco
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
      if (err) {
        console.error("Erro ao consultar o banco:", err);
        return res
          .status(500)
          .json({ message: "Erro no servidor ao consultar o banco." });
      }

      if (result.length > 0) {
        // Usuário já existe, retorna token JWT do sistema
        const user = result[0];
        const jwtToken = jwt.sign({ id: user.id, email: user.email }, SECRET, {
          expiresIn: "1h",
        });
        return res.json({ token: jwtToken, user });
      } else {
        // Criar novo usuário
        db.query(
          "INSERT INTO users (name, email, provider, provider_id) VALUES (?, ?, ?, ?)",
          [
            name || "Usuário Google",
            email,
            decodedToken.firebase.sign_in_provider,
            uid,
          ],
          (insertErr, insertResult) => {
            if (insertErr) {
              console.error("Erro ao criar usuário no banco:", insertErr);
              return res
                .status(500)
                .json({ message: "Erro no servidor ao criar usuário." });
            }

            const newUser = {
              id: insertResult.insertId,
              name: name || "Usuário Google",
              email,
              provider: decodedToken.firebase.sign_in_provider,
            };
            const jwtToken = jwt.sign(
              { id: newUser.id, email: newUser.email },
              SECRET,
              { expiresIn: "1h" }
            );
            return res.json({ token: jwtToken, user: newUser });
          }
        );
      }
    });
  } catch (err) {
    console.error("Erro ao verificar token do Firebase:", err);
    return res.status(403).json({ message: "Token inválido!" });
  }
});

// Rota Protegida (Exemplo)
app.get("/", authenticateToken, (req, res) => {
  res.json({ message: `Bem-vindo, usuário ${req.user.email}` });
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

// Endpoint para obter os dados do usuário
app.get("/user", authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = "SELECT name, email FROM users WHERE id = ?";
  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Erro ao buscar dados do usuário" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    res.json(results[0]); // Retorna os dados do usuário
  });
});

const multer = require("multer");
const path = require("path");

// Configuração para armazenamento do PDF usando multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Diretório onde os arquivos serão armazenados
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Nome único
  },
});

const upload = multer({ storage });

// Rota para adicionar livros
const { PDFDocument } = require("pdf-lib");
const poppler = require("pdf-poppler");

app.post("/add-book", upload.single("file"), async (req, res) => {
  const { title, author, totalPages, userId } = req.body;
  const filePath = req.file.path;

  if (!title || !author || !filePath || !userId || !totalPages) {
    return res
      .status(400)
      .json({ message: "Todos os campos são obrigatórios!" });
  }

  let coverPath = null;
  try {
    console.log("Iniciando a conversão do PDF...");
    const options = {
      format: "jpeg",
      out_dir: "./uploads",
      out_prefix: `${Date.now()}_cover_temp`, // Prefixo temporário
      page: 1, // Apenas a primeira página
    };

    // Converter PDF em imagem
    await poppler.convert(filePath, options);
    console.log("Conversão do PDF concluída.");

    // Calcular o número de zeros no sufixo do arquivo
    const zerosNeeded = totalPages.toString().length - 1;
    const zeroPaddedSuffix = `${"0".repeat(zerosNeeded)}1`; // Exemplo: "01", "001", etc.

    const possibleCoverPath = `${options.out_dir}/${options.out_prefix}-${zeroPaddedSuffix}.jpg`;

    if (fs.existsSync(possibleCoverPath)) {
      coverPath = possibleCoverPath;
    } else {
      throw new Error(
        `Arquivo de capa esperado não encontrado: ${possibleCoverPath}`
      );
    }
  } catch (error) {
    console.error("Erro ao extrair capa do PDF:", error.message);
    return res
      .status(500)
      .json({ message: "Erro ao processar o arquivo PDF." });
  }

  // Salvar no banco de dados
  const query = `
    INSERT INTO books (user_id, title, author, total_pages, file_path, cover_path, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
  `;

  db.query(
    query,
    [userId, title, author, totalPages, filePath, coverPath],
    (err) => {
      if (err) {
        console.error("Erro ao adicionar livro:", err);
        return res.status(500).json({ message: "Erro ao adicionar livro" });
      }
      res.status(201).json({ message: "Livro adicionado com sucesso!" });
    }
  );
});

app.get("/user-books/:userId", (req, res) => {
  const { userId } = req.params;

  const query =
    "SELECT id, title, author, total_pages, file_path, cover_path FROM books WHERE user_id = ?";
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Erro ao buscar livros do usuário:", err);
      return res.status(500).json({ message: "Erro no servidor." });
    }

    res.status(200).json(results);
  });
});

app.get("/book-details/:bookId", (req, res) => {
  const { bookId } = req.params;

  const query = "SELECT * FROM books WHERE id = ?";
  db.query(query, [bookId], (err, result) => {
    if (err) {
      console.error("Erro ao buscar detalhes do livro:", err);
      return res.status(500).json({ message: "Erro no servidor." });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Livro não encontrado." });
    }

    res.status(200).json(result[0]);
  });
});

const fs = require("fs"); // Importa o módulo File System

app.delete("/delete-book/:bookId", (req, res) => {
  const { bookId } = req.params;

  const getFilePathsQuery =
    "SELECT file_path, cover_path FROM books WHERE id = ?";
  db.query(getFilePathsQuery, [bookId], (err, result) => {
    if (err) {
      console.error("Erro ao buscar caminhos dos arquivos:", err);
      return res.status(500).json({ message: "Erro no servidor." });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Livro não encontrado." });
    }

    const filePath = result[0].file_path;
    const coverPath = result[0].cover_path;

    // Exclui o registro do banco
    const deleteBookQuery = "DELETE FROM books WHERE id = ?";
    db.query(deleteBookQuery, [bookId], (err) => {
      if (err) {
        console.error("Erro ao excluir livro do banco de dados:", err);
        return res
          .status(500)
          .json({ message: "Erro no servidor ao excluir livro." });
      }

      // Verifica e exclui o PDF
      if (filePath && fs.existsSync(filePath)) {
        fs.unlink(filePath, (err) => {
          if (err) {
            console.error("Erro ao excluir arquivo PDF:", err);
          }
        });
      }

      // Verifica e exclui a capa
      if (coverPath && fs.existsSync(coverPath)) {
        fs.unlink(coverPath, (err) => {
          if (err) {
            console.error("Erro ao excluir imagem da capa:", err);
          }
        });
      }

      res
        .status(200)
        .json({ message: "Livro, arquivo PDF e capa excluídos com sucesso!" });
    });
  });
});

// ... (todo o seu código anterior, rotas de livros, delete, etc.)
// ===========================================
// ROTA: GET /get-progress/:userId/:bookId
// ===========================================
app.get("/get-progress/:userId/:bookId", (req, res) => {
  const { userId, bookId } = req.params;

  const sql = `
    SELECT current_page 
    FROM user_progress 
    WHERE user_id = ? AND book_id = ?
  `;
  db.query(sql, [userId, bookId], (err, results) => {
    if (err) {
      console.error("Erro ao buscar progresso:", err);
      return res
        .status(500)
        .json({ message: "Erro no servidor ao buscar progresso." });
    }

    // Se não encontrou nenhum registro, retornamos 404
    if (results.length === 0) {
      return res.status(404).json({ message: "Progresso não encontrado." });
    }

    // Se encontrou, retornamos o current_page
    res.status(200).json({
      user_id: userId,
      book_id: bookId,
      current_page: results[0].current_page,
    });
  });
});

// ===========================================
// ROTA: POST /update-progress
// ===========================================
app.post("/update-progress", (req, res) => {
  const { user_id, book_id, current_page } = req.body;

  if (!user_id || !book_id || !current_page) {
    return res.status(400).json({
      message: "Campos insuficientes (user_id, book_id, current_page).",
    });
  }

  // Verifica se já existe um registro de progresso para user_id + book_id
  const sqlSelect = `
    SELECT id FROM user_progress 
    WHERE user_id = ? AND book_id = ?
  `;
  db.query(sqlSelect, [user_id, book_id], (err, selectResults) => {
    if (err) {
      console.error("Erro ao verificar progresso existente:", err);
      return res
        .status(500)
        .json({ message: "Erro no servidor ao verificar progresso." });
    }

    // Se já existe registro, atualizamos
    if (selectResults.length > 0) {
      const progressId = selectResults[0].id;
      const sqlUpdate = `
        UPDATE user_progress 
        SET current_page = ?, updated_at = NOW() 
        WHERE id = ?
      `;
      db.query(sqlUpdate, [current_page, progressId], (errUpdate) => {
        if (errUpdate) {
          console.error("Erro ao atualizar progresso:", errUpdate);
          return res
            .status(500)
            .json({ message: "Erro no servidor ao atualizar progresso." });
        }
        return res
          .status(200)
          .json({ message: "Progresso atualizado com sucesso!" });
      });
    } else {
      // Se não existe, insere um novo
      const sqlInsert = `
        INSERT INTO user_progress (user_id, book_id, current_page, created_at, updated_at)
        VALUES (?, ?, ?, NOW(), NOW())
      `;
      db.query(sqlInsert, [user_id, book_id, current_page], (errInsert) => {
        if (errInsert) {
          console.error("Erro ao inserir progresso:", errInsert);
          return res
            .status(500)
            .json({ message: "Erro no servidor ao inserir progresso." });
        }
        return res
          .status(200)
          .json({ message: "Progresso inserido com sucesso!" });
      });
    }
  });
});
