const nodeMailer = require("nodemailer");
const smtpTransport = require("nodemailer-smtp-transport");

const transporterDetails = smtpTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
        user: "alirezatlb45@gmail.com",
        pass: "rtivwwtuwjkgohkl",
    },
    tls: {
        rejectUnauthorized: false,
    },
});

exports.sendEmail = (email, fullname, subject, message) => {
    const transporter = nodeMailer.createTransport(transporterDetails);

    const options = {
        from: "alirezatlb45@gmail.com",
        to: email,
        subject: subject,
        html: `<h!>سلام ${fullname}</h1>
            <p>${message}</p>`,
    };

    transporter.sendMail(options, (err, info) => {
        if (err) return console.log(err);
        console.log(info);
    });
}