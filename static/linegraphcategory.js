$( document ).ready(function(){
    var myRadarChart;

    var button = document.getElementById("createradarchart");

    button.onclick = function(){
        makeradarchart();
    };

        var numberinputbutton = document.getElementById("numberinputbutton");

        numberinputbutton.onclick = function(){

        $('#form').empty();

        var numberinput = parseInt(document.getElementById("numberinput").value, 10);
        var form = document.getElementById("form");

        for (var i = 0; i < numberinput; i++)
        {
            var x = i + 1;
            var div = document.createElement("div");
            var h3 = document.createElement("H3");

            div.setAttribute('class', 'box1');

            var labeltext = document.createElement("input");
            labeltext.setAttribute('class', 'form-control');
            labeltext.id = 'label' + i;
            labeltext.placeholder = 'Dataset Name';

            var textarea = document.createElement("textarea");
            text = document.createTextNode("Dataset" + " " + x);
            h3.appendChild(text);
            textarea.rows = '3';
            textarea.setAttribute('class', 'form-control');
            textarea.id = 'data' + i;
            textarea.placeholder = 'Data goes here: 1,2,3...';

            var colourselector = document.createElement("input");
            cstext = document.createTextNode("Colour Selector ");
            var picker = new jscolor(colourselector);
            picker.fromHSV(360 / 100, 100, 100);


            var direction1text = document.createTextNode("Fill Colour Direction ")

            var direction1 = document.createElement("select");
            direction1.setAttribute('class', 'adjust');
            var option1 = document.createElement("option");
            var option2 = document.createElement("option");
            option1.textContent = "To Right";
            option2.textContent = "To Top";
            direction1.appendChild(option1);
            direction1.appendChild(option2);
            direction1.id = 'direction1' + i;


            var colour = document.createElement("input");
            colourtext = document.createTextNode(" Start Colour ");
            colour.setAttribute('class', 'adjust');
            colour.type = 'text';
            colour.id = 'colour' + i;

            var colourend = document.createElement("input");
            colourendtext = document.createTextNode(" End Colour ");
            colourend.setAttribute('class', 'adjust');
            colourend.type = 'text';
            colourend.id = 'colourend' + i;

            var direction2text = document.createTextNode("Border Colour Direction ")

            var direction2 = document.createElement("select");
            direction2.setAttribute('class', 'adjust');
            var option3 = document.createElement("option");
            var option4 = document.createElement("option");
            option3.textContent = "To Right";
            option4.textContent = "To Top";
            direction2.appendChild(option3);
            direction2.appendChild(option4);
            direction2.id = 'direction2' + i;

            var colour2 = document.createElement("input");
            colour2text = document.createTextNode(" Start Colour ");
            colour2.setAttribute('class', 'adjust');
            colour2.type = 'text';
            colour2.id = 'colour2' + i;

            var colour2end = document.createElement("input");
            colour2endtext = document.createTextNode(" End Colour ");
            colour2end.setAttribute('class', 'adjust');
            colour2end.type = 'text';
            colour2end.id = 'colour2end' + i;

            var borderw = document.createElement("input");
            borderwtext = document.createTextNode(" Border Width ");
            borderw.setAttribute('class', 'adjust');
            borderw.type = 'number';
            borderw.id = 'borderwidth' + i;

            br = document.createElement("br");


            div.appendChild(h3);
            div.appendChild(labeltext);
            div.appendChild(br);
            div.appendChild(textarea);
            div.appendChild(br.cloneNode());
            div.appendChild(cstext);
            div.appendChild(colourselector);
            div.appendChild(br.cloneNode());
            div.appendChild(br.cloneNode());
            div.appendChild(direction1text);
            div.appendChild(direction1);
            div.appendChild(colourtext);
            div.appendChild(colour);
            div.appendChild(colourendtext);
            div.appendChild(colourend);
            div.appendChild(br.cloneNode());
            div.appendChild(br.cloneNode());
            div.appendChild(direction2text);
            div.appendChild(direction2);
            div.appendChild(colour2text);
            div.appendChild(colour2);
            div.appendChild(colour2endtext);
            div.appendChild(colour2end);
            div.appendChild(br.cloneNode());
            div.appendChild(br.cloneNode());
            div.appendChild(borderwtext);
            div.appendChild(borderw);
            form.appendChild(div);
        }
        };


    function makeradarchart(){
        var datasets = [];
        var ctxR = document.getElementById("radarchart").getContext('2d');

        var numberinput = parseInt(document.getElementById("numberinput").value, 10);
        for (var j = 0; j < numberinput; j++)
        {
            var label = document.getElementById("label" + j).value;
            var data = document.getElementById("data" + j).value.split(",");
            var colour = document.getElementById("colour" + j).value;
            var colour2 = document.getElementById("colour2" + j).value;
            var borderwidth = document.getElementById("borderwidth" + j).value;
            var colourend = document.getElementById("colourend" + j).value;
            var colour2end = document.getElementById("colour2end" + j).value;
            var direction1 = document.getElementById("direction1" + j).value;
            var direction2 = document.getElementById("direction2" + j).value;

            // for fill colour
            if (direction1 == "To Right"){
                var gradient = ctxR.createLinearGradient(0, 0, 1068, 0);
                gradient.addColorStop(0, colour);
                gradient.addColorStop(1, colourend);
            }
            else if (direction1 == "To Top"){
                var gradient = ctxR.createLinearGradient(0, 421, 0, 0);
                gradient.addColorStop(0, colour);
                gradient.addColorStop(1, colourend);
            }

            // for border colour
            if (direction2 == "To Right"){
                var bordergradient = ctxR.createLinearGradient(0, 0, 1068, 0);
                bordergradient.addColorStop(0, colour2);
                bordergradient.addColorStop(1, colour2end);
            }
            else if (direction2 == "To Top"){
                var bordergradient = ctxR.createLinearGradient(0, 0, 0, 421);
                bordergradient.addColorStop(0, colour2);
                bordergradient.addColorStop(1, colour2end);
            }

            datasets.push({label:label, data:data, backgroundColor:gradient, borderColor:bordergradient, borderWidth:borderwidth, showLine:true},);
            console.log(datasets);
        }


        var title = document.getElementById("title").value;
        var min = document.getElementById("min").value;
        var max = document.getElementById("max").value;
        var step = document.getElementById("step").value;
        var variables = document.getElementById("variables").value.split(",");

        //radar
        var ctxR = document.getElementById("radarchart").getContext('2d');
        myRadarChart = new Chart(ctxR, {
            type: 'line',
            data: {
                labels: variables,
                datasets: datasets
            },
            options:{
                title: {
                    display: true,
                    text: title
                },
                scales: {
                    yAxes: [{
                        ticks: {
                        min: parseFloat(min),
                        max: parseFloat(max),
                        stepSize: parseFloat(step)
                        },
                    }],
                },
                responsive: true
            },
        });
        // Background Colour
        var radarchart = document.getElementById("radarchart");
        var backgroundcolour = document.getElementById("backgroundcolour").value;
        radarchart.style.backgroundColor = backgroundcolour;
    }


    // download function
    $('#radardownload').click(function(){
        html2canvas(document.querySelector('#radarchart')).then(function(canvas) {

            console.log(canvas);
            saveAs(canvas.toDataURL(), 'mycanvas.png');
        });
    });

    function saveAs(uri, filename) {

    var link = document.createElement('a');

    if (typeof link.download === 'string') {

        link.href = uri;
        link.download = filename;

        //Firefox requires the link to be in the body
        document.body.appendChild(link);

        //simulate click
        link.click();

        //remove the link when done
        document.body.removeChild(link);

    } else {

        window.open(uri);

    }
    }

});