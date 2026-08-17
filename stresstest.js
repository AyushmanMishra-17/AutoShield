import http from "k6/http";

export const options = {
  vus: 10,        // virtual users
  duration: "10s" // test time
};

export default function () {
  http.get("http://localhost:5000/test");
}