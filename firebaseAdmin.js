const admin = require("firebase-admin");
const serviceAccount = require("./my-book-reader-712ee-firebase-adminsdk-mnqmn-3e9b4b488c.json"); // Substitua pelo caminho correto

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

module.exports = admin;
