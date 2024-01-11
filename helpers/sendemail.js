const nodemailer = require("nodemailer");
const dotenv = require("dotenv");

dotenv.config();

const UKR_NET_EMAIL = process.env.UKR_NET_EMAIL;
const UKR_NET_PASSWORD = process.env.UKR_NET_PASS;

const nodemailerConfig = {
  host: "smtp.ukr.net",
  port: 465, // 25,465,2525
  secure: true,
  auth: {
    user: UKR_NET_EMAIL,
    pass: UKR_NET_PASSWORD,
  },
};

const transport = nodemailer.createTransport(nodemailerConfig);

// const email = {
//   from: UKR_NET_EMAIL,
//   to: "silatop692@pursip.com",
//   subject: "Test email NODEMAILER",
//   html: "<strong>Test email NODEMAILER</strong>",
// };

// transport
//   .sendMail(email)
//   .then(() => console.log("Email sent successfully"))
//   .catch((err) => console.log(err));

const sendEmail = async (data) => {
  const email = { ...data, from: UKR_NET_EMAIL };
  return transport
    .sendMail(email)
    .then(() => console.log("Email sent successfully"))
    .catch((err) => console.log(err));
};
module.exports = { sendEmail };
