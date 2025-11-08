const bcrypt = require('bcrypt');
const uuid = require('uuid');
const nodemailer = require('nodemailer');
require('dotenv').config()
const transporter = nodemailer.createTransport({
    service: 'Gmail', 
    host: 'smtp.gmail.com',
    port : 465,
    secure : true,
    auth: {
      user: process.env.APP_EMAIL,
      pass: process.env.APP_PASSWORD,
    }
  });
 async function SendVerifCode(mail,Name,verificationCode,verificationLink){
    try{
console.log(verificationLink)
        const mailOptions = {
            from: 'All Tunsia Para',
            to: mail,
            subject: 'Account Verification',
            text: ``,
            html: `Hi , ${Name} Your  verification code is: ${verificationCode} , Click the following link to verify your account: <a href="${verificationLink}">${verificationLink}</a>`,
          };

          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error('Error sending verification email:', error);
            } else {
              console.log('Verification email sent:', info.response);
            }
          });

return true;
    }catch(err){
        console.log("sending mails Error ", err);
        return false;
    }
}
async function SendBookigNotificationMail(Admins){
try{
  Admins.forEach((admin)=>{
    const mailOptions = {
      from: 'All Tunsia Para',
      to: admin.email,
      subject: 'New Order',
      text: ``,
      html: 
''
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending verification email:', error);
        return false;
      } else {
        console.log('Notifications mails sent :', info.response);
        return true;
      }
    })
  })

}catch(err){
  console.log('error sending book notification by mail ',err)
  return err;
}
}

async function ReplayToContact(mail){
  try{
    const mailOptions = {
      from: 'All Tunsia Para',
  
      to: mail.email,
      subject: 'Replay to your latest Message',
      text: ``,
      html: 

`
      <p>
        <b>To:</b> ${mail.name} <br />
        <b>Message:</b> ${mail.message} <br />

      </p>`
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending verification email:', error);
        return false;
      } else {
        console.log('Notifications mails sent :', info.response);
        return true;
      }
    })
  
  }catch(err){
    console.log('error sending book notification by mail ',err)
    return err;
  }
  }
async function SendAbonnement(array) {
  try{
    const mailOptions = {
      from: 'All Tunsia Para',
  
      to: array.email,
      subject: 'new post added',
      text: ``,
      html: 

`
      <p>
        <b>To:</b> ${array.name} <br />
        <b>subject:</b> ${array.message} <br />
    <a href="https://alltunisiapara.com/${array.link}" target="_blank">${array.link}</a>

      </p>`
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending verification email:', error);
        return false;
      } else {
        console.log('Notifications mails sent :', info.response);
        return true;
      }
    })
  
  }catch(err){
    console.log('error sending book notification by mail ',err)
    return err;
  }
  
}
module.exports = {SendVerifCode, SendBookigNotificationMail,ReplayToContact, SendAbonnement};