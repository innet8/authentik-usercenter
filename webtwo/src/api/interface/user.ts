/* eslint-disable @typescript-eslint/no-namespace */
export namespace User {
    // 用户信息
    export interface Info {
        id: number
        email: string
        name: string
        token: string
        avatar: string
        created_at: string
        updated_at: string
        userIsAdmin: boolean
        identity: any
        department_owner: any
        userid: any
        department: any
    }

    // 登录请求
    export interface LoginReq {
        email: string
        username: string
        password: string
        pic_code?: string
        source_url?: any
    }

    // 注册请求
    export interface RegReq {
        username: string
        password: string
        password2?: string
        source?: string
        source_url?: any
    }

    // 注册请求
    export interface resendData {
        username: string
        language: any
    }
    // 注册请求
    export interface resetData {
        step: Number
        username?: any
        link_code?: any
        new_password?: any
        source_url?: any
    }

    // 是否需要验证码
    export interface needCode {
        username?: string
    }

    // 获取验证码图片
    export interface codeImg {
        captcha_id: string
        image_path: string
    }

    // 获扫码登录状态
    export interface qrcode {
        code?: string
    }

    // 重置密码
    export interface resetPassword {
        id?: any
        new_password?: any
        old_password?: any
    }

    // 发送邮箱验证码
    export interface sendEmailCode {
        email?: any
    }

    // 邮箱修改
    export interface changeEmail {
        email?: any
        id?: any
    }

}
