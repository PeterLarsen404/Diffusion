import "../utils/linalg"

def dense [m][n] (input : [n]f64) (weights : [m][n]f64) (biases : [m]f64) : [m]f64 =
    map2 (\ w b -> (dotprod input w) + b) weights biases

def dense_b [m][n] (out_grad : [m]f64) (dense_input : [n]f64) (weights : [m][n]f64) : ([n]f64, [m][n]f64, [m]f64) =
  let ws_g :[m][n]f64 = map (\ x -> map (\ y -> y*x) dense_input) out_grad
  let input_g = map (\ w -> dotprod w out_grad) (transpose weights)
  in (input_g, ws_g, out_grad)