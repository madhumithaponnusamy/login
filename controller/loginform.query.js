// Queries for authentication module

const SELECTUserByUserName = `
  SELECT userId, userName, password 
  FROM user 
  WHERE userName = ? AND password = ? AND deletedAt IS NULL
`;



module.exports = {
  SELECTUserByUserName
};
