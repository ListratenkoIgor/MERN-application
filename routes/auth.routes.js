const {Router} = require('express')
const bcrypt = require('bcryptjs')
const {check,validationResult} = require('express-validator')
const router = Router()
const User = require('../models/User')


// /api/auth/register
router.post(
    '/register',
    [
        check('email','wrong email').isEmail(),
        check('password','wrong password').isLength({min: 6})
    ]
    ,
    async (request,response)=>{
    try{
        const errors = validationResult(request)
        if(!errors.isEmpty()){
            response.status(400).json({errors: errors.array(),message:'invalid data'})
            return
        }

        const {email,password}=request.body;
        const candidate = await User.findOne({email})
        if(candidate){
            response.status(400).json({message:'This email is already register'})
            return
        }
        const hashedPassword = await bcrypt.hash(password,12)
        const user =new User({email,password: hashedPassword})

        await user.save()

        response.status(201).json({message:'User successfully created'})
    }catch(e){
        response.status(500).json({message:'Server fault. Try again'})

    }
})

// /api/auth/login
router.post(
    '/login',
    [
        check('email','wrong email').isEmail(),
        check('password','wrong password').isLength({min: 6})
    ]
    ,
    async (request,response)=>{
        try{
            const errors = validationResult(request)
            if(!errors.isEmpty()){
                response.status(400).json({errors: errors.array(),message:'invalid data'})
                return
            }
            const {email,password}=request.body;
            const user = await User.findOne({email})
            if(!user){
                response.status(400).json({message:'wrong email or password'})
                return
            }

            const isMatch = await bcrypt.compare(password,user.password)
            if(!isMatch){
                response.status(400).json({message:'wrong email or password'})
                return
            }

        }catch(e){
            response.status(500).json({message:'Server fault. Try again'})

        }
})
module.exports = router