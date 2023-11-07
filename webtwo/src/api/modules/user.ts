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
    return http.get<boolean>("user/login/needcode", params)
}
