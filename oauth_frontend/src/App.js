import './App.css';
import {BrowserRouter as Router, Route, Routes} from 'react-router-dom';
import UserInfo from "./screens/UserInfo"
import Login from "./screens/Login";

function App() {


  return (
    <div className="App">

        <Router>

            <Routes>
                <Route path="/" element={<Login />} />
                <Route path="/user/info" element={<UserInfo />} />
            </Routes>
        </Router>
    </div>
  );
}

export default App;
