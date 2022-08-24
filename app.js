require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const User = require('./modules/User')

//Rota pública
app.get('/', (req, res) => {
    res.status(200).json({msg: "Bem vindo!"})
})


//Rota privada
app.get("/user/:id", async (req, res) => {
    const id = req.params.id

    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({msg: 'Usuário não encontrado.'})
    }

    res.status(200).json({ user })
})



function checkToken(req, res, next){
const authHeader = req.headers['authorization']
const token = authHeader && authHeader.split("")[1]

if(!token){
    return res.status(401).json({msg: 'Acesso negado.'})
}

try {
    const secret = process.env.SECRET
    jwt.verify(token, secret)
    next()
} catch(error) {
    return res.status(401).json({msg: 'Token inválido!'})
}
}



app.post('auth/register', async(req, res) => {
    const {name, email, password, confirmpassword} = req.body

    if (!name) {
        return res.status(422).json({msg: 'O nome é obrigatório!'})
    }

    if (!email) {
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }

    if (!email) {
        return res.status(422).json({msg: 'A senha é obrigatória!'})
    }

    if (password !== confirmpassword) {
        return res.status(422).json({msg: 'As senhas não conferem.'})
    }

    const userExists = await User.findOne({email: email})

    if(userExists) {
        return res.status(422).json({msg: 'Email já cadastrado'})
    }

    const salt = await bcryppt.genSalt(12)
    const passwordhash = await bcrypt.hash(password, salt)

    const user = new User({
        name,
        email,
        password: passwordhash,
    })

    try {

        await user.save()
        res.status(201).json({msg: 'Usuário criado com sucesso!'})

    } catch(error) {
        console.log(error)
        res.status(500).json({msg: 'Aconteceu um erro no servidor, tente novamente mais tarde.'})
    }
})


//Login
app.post("/auth/user", async (req, res) => {
    const { email, password } = req.body

    if (!email) {
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }

    if (!password) {
        return res.status(422).json({msg: 'A senha é obrigatória!'})
    }

    const user = await User.findOne({email: email})

    if(!user) {
        return res.status(422).json({msg: 'Usuário não encontrado'})
    }

    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({msg: 'Senha inválida'})
    }


    try {
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._ud,
        },
        secret,
        )

        res.status(200).json({ msg: 'Autenticação confirmada com sucesso.', token})

    } catch(err) {
        console.log(error)
        res.status(500).json({msg: 'Aconteceu um erro no servidor, tente novamente mais tarde.'})
    }
})


//Credenciais
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPassword}cluster0.5pfdguo.mongodb.net/?retryWrites=true&w=majority`,)
    .then(() =>{
        app.listen(3000)
        console.log('Conectado ao banco')
    })
    .catch((err) => console.log)
