// Queries for authentication module

const SELECTUserByUserName = `
  SELECT userId, userName, email, password 
  FROM user 
  WHERE userName = ? AND password = ? AND deletedAt IS NULL
`;



module.exports = {
  SELECTUserByUserName
};
