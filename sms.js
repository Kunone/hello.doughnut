const AWS = require('aws-sdk')
var creds = new AWS.SharedIniFileCredentials({profile: 'default'})
const sns = new AWS.SNS({
    region: 'ap-southeast-1',
    credentials: creds
})

async function sendMessage(message, number) {
    try {
        console.log("Sending Message")
        const result = await sns.publish({
            Message: message,
            PhoneNumber: number,
        }).promise()

        console.log(result)
    } catch (err) {
        console.log(err)
    }
}

sendMessage(process.argv[2], process.argv[3])