import axios from "axios";
import {ElMessage} from "element-plus";

const authItemName = "access_token"

const defaultFailure = (message, code, url) => {
    console.log(`Request to ${url} failed with code ${code} and message ${message}`)
    ElMessage.warning(message)
}

const defaultError = (err) => {
    console.log(err)
    ElMessage.warning(`发生了一些错误，请联系管理员`)
}

function takeAccessToken() {
    const str = localStorage.getItem(authItemName) || sessionStorage.getItem(authItemName)
    if (!str) {
        return null
    }
    const authObj = JSON.parse(str)
    if (authObj.expire <= Date.now()) {
        deleteAccessToken()
        ElMessage.warning('登录已过期，请重新登录')
        return null
    }
    return authObj.token
}

function storeAccessToken(token, remember, expire) {
    const authObj = {token: token, expire: expire}
    const str = JSON.stringify(authObj)
    if (remember) {
        localStorage.setItem(authItemName, str)
    } else {
        sessionStorage.setItem(authItemName, str)
    }
}

function deleteAccessToken() {
    localStorage.removeItem(authItemName)
    sessionStorage.removeItem(authItemName)
}

function accessHeader() {
    const token = takeAccessToken()
    return token ? {'Authorization': `Bearer ${takeAccessToken()}`} : {}
}

function internalPost(url, data, header, success, failure, error = defaultError) {
    axios.post(url, data,{headers: header}).then(({data}) => {
        if (data.code === 200) {
            success(data.data)
        } else {
            failure(data.message, data.code, url)
        }
    }).catch(err => error(err))
}

function internalGet(url, header, success, failure, error = defaultError) {
    axios.get(url,{headers: header}).then(({data}) => {
        if (data.code === 200) {
            success(data.data)
        } else {
            failure(data.message, data.code, url)
        }
    }).catch(err => error(err))
}

function get(url, success, failure = defaultFailure) {
    internalGet(url, accessHeader(), success, failure)
}

function post(url, data, success, failure = defaultFailure) {
    internalPost(url, data, accessHeader(), success, failure)
}

function login(username, password, remember, success, failure = defaultFailure) {
    internalPost('/api/auth/login', {
        username: username,
        password: password,
        remember: remember,
    }, {
        'Content-Type': 'application/x-www-form-urlencoded'
    }, (data) => {
        storeAccessToken(data.token, remember, data.expire)
        ElMessage.success('登录成功')
        success(data)
    }, failure)
}

function logout(success, failure = defaultFailure) {
    get('/api/auth/logout', () => {
        deleteAccessToken()
        ElMessage.success('退出登录成功')
        success()
    }, failure)
}

function unauthorized() {
    return !takeAccessToken()
}

export {login, logout, get, post, unauthorized}
