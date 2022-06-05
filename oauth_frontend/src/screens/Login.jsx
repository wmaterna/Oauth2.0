import React from "react";

function Login() {

    const handleLogin = (path) => {
        window.location.assign(`http://localhost:8080` + path)
    }

    return (
        <div>
            <p><button onClick={() => handleLogin("/login-google")}>Login Google</button></p>
            <p><button onClick={() => handleLogin("/login-github")}>Login GitHub</button></p>
        </div>
    );
}

export default Login;