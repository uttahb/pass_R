

const password_recovery_fn = async (req, res) => {

  // health check
  if (req.params["health"] === "health") {
    res.write(JSON.stringify({success: true, msg: "Health check success"}))
    res.end()
  }

  // Add your code here
  res.write(JSON.stringify({success: true, msg: `Hello password_recovery_fn`}))
  res.end()
  
}

export default password_recovery_fn
