// Minimal program exercising the one real dependency pulled through the proxy.
import 'package:path/path.dart' as p;

void main() {
  print(p.join('pulled', 'through', 'proxy'));
}
