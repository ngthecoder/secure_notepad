int main(){
	
	printf("Welcome to Secure Notepad!");
	printf("Please Log in:\n");

	int option;
	menu();
	scanf("%d", &option);
	
	switch(){
		case 1:
			break;		
		case 2:
			break;		
		case 3:
			break;		
		case 4:
			break;		
		case 5:
			break;		
		case 6:
			break;
		default:
			printf("Invalid Input.\n");
	}
	return 0;
}

void menu(){
	printf("Choose an option: \n");
	printf("1. Create new key pair\n");
	printf("2. View your key\n");
	printf("3. Create a message\n");
	printf("4. View your unencrypted message\n");
	printf("5. Delete your message\n");
	printf("6. Exit\n");
}

