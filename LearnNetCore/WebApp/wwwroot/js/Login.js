//var formLogin = {
//    saveLogin: function () {

//        //if ($('#formLogin').parsley().validate()) {
//            //var dataResult = getJsonForm($("#formLogin").serializeArray(), true);
//        var dataResult = {
//            Email: $('#Username').val(),
//            Password : document.getElementById("password").value
//        }
//        console.log(dataResult);
//            $.ajax({
//                url: '/login/CreateLoginAsync',
//                method: 'post',
//                contentType: 'application/json',
//                dataType: 'json',
//                data: JSON.stringify(dataResult),
//                success: function (res, status, xhr) {
//                    if (xhr.status == 200 || xhr.status == 201) {

//                        if (res) {
//                            window.location.replace("http://localhost:44390/dashboard")

//                        } else {

//                            window.alert("Either your username or password was incorrect. Please try again.");
//                        }

//                    } else {
//                        console.log('check2');

//                    }
//                },
//                error: function (xhr, status, error) {
//                    //var err = eval("(" + xhr.responseText + ")");
//                    //console.log(err.Message);
//                }
//            });
//        //}
//    }

//};
//$("#login").click(function () {
//    formLogin.saveLogin();
//});
//$(document).on('click', '#submit', function (e) {
//    e.preventDefault();
//    swal({
//        title: 'Confirmation',
//        input: 'checkbox',
//        inputValue: 0,
//        inputPlaceholder: 'Do you want to log in?',
//        showCancelButton: true,
//        cancelButtonText: 'Cancel',
//        confirmButtonText: 'Yes, I do',
//        inputValidator: function (result) {
//            return new Promise(function (resolve) {
//                if (result) {
//                    resolve();
//                    formDivision.saveForm();
//                } else {
//                    resolve("Please check confirmation button")
//                }
//            })
//        }
//    }).then(function (result) {
//        $('#formLogin').submit();
//    });
//});

function myLogin() {
	var validate = new Object();
	validate.Email = $('#Username').val();
	validate.Password = $('#password').val();
	console.log(validate);
	$.ajax({
		type: 'POST',
		url: "/validate/",
		cache: false,
		dataType: "JSON",
		data: validate
	}).then((result) => {
		if (result.status == true) {
			window.location.href = "/";
		} else {
			toastr.warning("Incorrect password or " + result.msg)
		}
	})
};

function Register() {
    var confirm = $("#confirmPassword").val();
    var pw = $("#password").val();
    if (confirm == pw) {
        var dataRegister = {
            username: $("#username").val(),
            email: $("#email").val(),
            password: $("#password").val(),
            phone: $("#phone").val(),
            confirmPassword: $("#confirmPassword").val()
        };
        console.log(dataRegister);
        $.ajax({
            type: 'POST',
            url: "/regisvalidate/",
            cache: false,
            dataType: "JSON",
            data: dataRegister
        }).then((result) => {
            if (result.status == true) {
                toastr.success("register successfully")
                window.location.href = "/";
            } else {
                toastr.warning(result.msg)
            }
        })
    } else {
        toastr.warning(result.msg)
    }
};
