const express = require('express')
const app = express()
app.use(express.json())
const cors = require('cors')
app.use(cors()) // Needed for Render

const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const bcrypt = require('bcrypt')

const filePath = path.join(__dirname, 'db','userData.db')
let db = null

const init = async () => {
  try {
    db = await open({
      filename: filePath,
      driver: sqlite3.Database,
    })

    const port = process.env.PORT || 3000
    app.listen(port, () => {
      console.log(`✅ Server started at ${port}`)
    })
  } catch (e) {
    console.log(`DB Error: ${e}`)
    process.exit(1)
  }
}

// REGISTER
app.post('/register', async (request, response) => {
  const {username, name, password, gender, location} = request.body

  const selectQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectQuery, [username])

  if (dbUser === undefined) {
    if (password.length < 5) {
      return response.status(400).send('Password is too short')
    }
    const hashedPassword = await bcrypt.hash(password, 10)
    const insertQuery = `
      INSERT INTO user (username, name, password, gender, location)
      VALUES (?, ?, ?, ?, ?)
    `
    await db.run(insertQuery, [
      username,
      name,
      hashedPassword,
      gender,
      location,
    ])
    response.status(200).send('User created successfully')
  } else {
    response.status(400).send('User already exists')
  }
})

// LOGIN
app.post('/login', async (request, response) => {
  const {username, password} = request.body

  const selectQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectQuery, [username])

  if (dbUser === undefined) {
    return response.status(400).send('Invalid user')
  }

  const isPasswordCorrect = await bcrypt.compare(password, dbUser.password)
  if (isPasswordCorrect) {
    response.status(200).send('Login success!')
  } else {
    response.status(400).send('Invalid password')
  }
})

// CHANGE PASSWORD
app.put('/change-password', async (request, response) => {
  const {username, oldPassword, newPassword} = request.body

  const selectQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectQuery, [username])

  if (dbUser === undefined) {
    return response.status(400).send('User not found')
  }

  const isPasswordCorrect = await bcrypt.compare(oldPassword, dbUser.password)
  if (isPasswordCorrect) {
    if (newPassword.length < 5) {
      return response.status(400).send('Password is too short')
    }
    const hashedNewPassword = await bcrypt.hash(newPassword, 10)
    const updateQuery = `UPDATE user SET password = ? WHERE username = ?`
    await db.run(updateQuery, [hashedNewPassword, username])
    response.status(200).send('Password updated')
  } else {
    response.status(400).send('Invalid current password')
  }
})


init()
module.exports = app
 
