
const multer = require("multer");
const path = require("path");

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "upload");
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const username = req.body.username;

        if (!username) return cb(new Error("Username missing"));

        // 🔑 ONLY CHANGE: timestamp add
        const filename = `${username}Profile_${Date.now()}${ext}`;

        cb(null, filename);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 }
});

module.exports = upload;