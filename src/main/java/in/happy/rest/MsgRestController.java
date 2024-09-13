package in.happy.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MsgRestController {
	@GetMapping("/contect")
	public String contect() {
		return "6203332535";
	}
	
	@GetMapping("/greet")
	public String greetController() {
		return "Namaste";
	}
	@GetMapping("/welcome")
	public String welcome() {
		return "welcome to india";
	}

}
