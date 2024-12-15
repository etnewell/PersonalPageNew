// frontend/src/services/authService.js
import axios from 'axios';

const API_URL = 'http://localhost:5000/api/users/';

export const register = async (userData) => {
    const response = await axios.post(API_URL + 'register', userData);
    return response.data;
};

export const login = async (userData) => {
    const response = await axios.post(API_URL + 'login', userData);
    if (response.data.token) localStorage.setItem('user', JSON.stringify(response.data));
    return response.data;
};
