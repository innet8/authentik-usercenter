import http from "../index"
import { User } from "../interface/user"

export const getUserInfo = () => {
    return http.get<User.Info>("user/info")
}

export const userLogin = (params: User.LoginReq) => {
    return http.post<User.Info>("core/users/login/", params)
}

export const userReg = (params: User.RegReq) => {
    return http.post<User.Info>("core/users/register/", params)
}

export const needCode = (params: User.needCode) => {
    return http.get<any>("/core/users/needCode/", params)
}


//重新发送邮件
export const resend = (params: User.resendData) => {
    return http.post<User.Info>("/core/users/sendRegisterVerifyEmail/", params)
}
//找回密码发送邮件
export const retrievePassword = (params: User.resendData) => {
    return http.post<User.Info>("/core/users/retrieve_password", params)
}

//邮件激活
export const verifyRegisterEmail = (params: any) => {
    return http.get<any>("/core/users/verifyRegisterEmail/", params)
}