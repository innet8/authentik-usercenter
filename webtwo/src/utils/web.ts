/**
 * 页面专用
 */
window.systemInfo = window.systemInfo || {}
const webTs = {
    /**
     * 接口地址
     * @param str
     * @returns {string|string|*}
     */
    apiUrl(str) {
        if (
            str.substring(0, 2) === "//" ||
            str.substring(0, 7) === "http://" ||
            str.substring(0, 8) === "https://" ||
            str.substring(0, 6) === "ftp://" ||
            str.substring(0, 1) === "/"
        ) {
            return str
        }
        if (typeof window.systemInfo.apiUrl === "string") {
            str = window.systemInfo.apiUrl + str
        } else {
            str = window.location.origin + "/api/" + str
        }
        while (str.indexOf("/../") !== -1) {
            str = str.replace(/\/(((?!\/).)*)\/\.\.\//, "/")
        }
        return str
    },
    // 获取url参数
    getRequest(url, key) {
        var theRequest = new Object();
        if (url.indexOf("?") != -1) {
            var str = url.split("?")[1] || [];
            var strs = str.split("&");
            for(var i = 0; i < strs.length; i ++) {
                theRequest[strs[i].split("=")[0]] =  decodeURI(decodeURIComponent(
                    decodeURI(decodeURIComponent(
                        escape(strs[i].split("=")[1]).replace(/\+/g, '%20')
                    ))
                ));
            }
        }
        return key ? theRequest[key] : theRequest;
    },
    // 添加参数
    addParamToUrl(url, key, value) {
        const urlParts = url.split('?');
        let baseUrl = urlParts[0];
        let queryString = urlParts[1] || '';

        // 将参数字符串转换为对象
        let params = {};
        queryString.split('&').forEach(item => {
            if (item) {
                let parts = item.split('=');
                params[parts[0]] = parts[1];
            }
        });

        // 移除已有参数中的同名key
        delete params[key];

        // 添加新参数
        let updatedQueryString = Object.keys(params)
            .map(key => `${key}=${params[key]}`)
            .join('&');

        let updatedUrl = baseUrl + (updatedQueryString ? `?${updatedQueryString}` : '');

        if (updatedUrl.includes('?')) {
            updatedUrl += `&${key}=${value}`;
        } else {
            updatedUrl += `?${key}=${value}`;
        }

        return updatedUrl;
    },
    // 删除参数
    delParamToUrl(url, key) {
        // 创建一个 URL 对象
        url = new URL(url);
        // 从 URL 对象中删除指定参数
        url.searchParams.delete(key);
        // 生成新的 URL
        return url.href;
    }
}
export default webTs
