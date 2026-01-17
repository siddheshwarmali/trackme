
let users = [{ id: 1, name: "Admin", email: "admin@trackwise.com" }];

exports.handler = async (event) => {
  if (event.httpMethod === "GET") {
    return {
      statusCode: 200,
      body: JSON.stringify(users)
    };
  }

  if (event.httpMethod === "POST") {
    const data = JSON.parse(event.body);
    const newUser = { id: Date.now(), ...data };
    users.push(newUser);
    return {
      statusCode: 200,
      body: JSON.stringify(newUser)
    };
  }

  if (event.httpMethod === "DELETE") {
    const { id } = JSON.parse(event.body);
    users = users.filter(u => u.id !== id);
    return {
      statusCode: 200,
      body: JSON.stringify({ success: true })
    };
  }

  return { statusCode: 405, body: "Method Not Allowed" };
};
