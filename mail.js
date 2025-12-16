const nodemailer = require("nodemailer");
let transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user:  process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

async function sendMail(to, subject, message) {
    try {
        let result = await transporter.sendMail({
            from:  process.env.EMAIL_USER,
            to: to,
            subject: subject,
            text: message,
        });
        return result
    } catch (error) {
        return error
    }
}


module.exports = sendMail