
const checkUserExists = `
    SELECT * FROM userlogin
    WHERE (username = ? OR email = ?)
    AND deletedAt IS NULL
`;


const insertUser = `
    INSERT INTO userlogin (username, email, password, profilePath, createdAt, updatedAt)
    VALUES (?, ?, ?, ?, NOW(), NOW())
`;


const getUser = `
    SELECT * FROM userlogin
    WHERE username = ? AND deletedAt IS NULL
`;

const getUserByEmail = `
    SELECT * FROM userlogin
    WHERE email = ? AND deletedAt IS NULL
`;


const updatePasswordByEmail = `
    UPDATE userlogin
    SET password = ?, updatedAt = NOW()
    WHERE email = ? AND deletedAt IS NULL
`;

  const getProfileByUserId = `
        SELECT profilePath 
        FROM userlogin 
        WHERE userId = ?
    `;
   const updateProfileByUserId = `
        UPDATE userlogin 
        SET profilePath = ?
        WHERE userId = ?`

module.exports = {
    checkUserExists,
    insertUser,
    getUser,
    getUserByEmail,
    updatePasswordByEmail,
    getProfileByUserId,
    updateProfileByUserId
};
