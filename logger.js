module.exports = {
    saveLog: (db, log) => {
        const sql = `
            INSERT INTO applogs (reqId, level, msg, meta)
            VALUES (?, ?, ?, ?)
        `;

        const params = [
            log.reqId || null,
            log.level,
            log.msg,
            JSON.stringify(log.meta || {})
        ];

        db.query(sql, params, (err) => {
            if (err) console.error("DB Log Insert Error:", err);
        });
    }
};