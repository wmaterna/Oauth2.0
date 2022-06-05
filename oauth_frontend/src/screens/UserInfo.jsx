import React, {useEffect, useState} from "react";
import Cookies from "js-cookie";


function UserInfo() {
    const [token, setToken] = useState("");
    useEffect(() => {
        setToken(Cookies.get("jwt-token"))
    },[])
    return (
        <div>
            { token !== "" &&
                <p>JWT Token received by frontend: {token}</p>
            }
        </div>
    );
}

export default UserInfo;