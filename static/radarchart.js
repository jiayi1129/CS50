$( document ).ready(function(){


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

            var colour = document.createElement("input");
            colourtext = document.createTextNode(" Fill Colour ");
            colour.setAttribute('class', 'adjust');
            colour.type = 'text';
            colour.id = 'colour' + i;

            var colour2 = document.createElement("input");
            colour2text = document.createTextNode(" BorderColour ");
            colour2.setAttribute('class', 'adjust');
            colour2.type = 'text';
            colour2.id = 'colour2' + i;

            var borderw = document.createElement("input");
            borderwtext = document.createTextNode(" BorderWidth ");
            borderw.setAttribute('class', 'adjust');
            borderw.type = 'number';
            borderw.id = 'borderwidth' + i;

            br = document.createElement("br");


            div.appendChild(h3);
            div.appendChild(labeltext);
            div.appendChild(br.cloneNode());
            div.appendChild(textarea);
            div.appendChild(br);
            div.appendChild(br.cloneNode());
            div.appendChild(cstext);
            div.appendChild(colourselector);
            div.appendChild(br);
            div.appendChild(br.cloneNode());
            div.appendChild(colourtext);
            div.appendChild(colour);
            div.appendChild(colour2text);
            div.appendChild(colour2);
            div.appendChild(borderwtext);
            div.appendChild(borderw);
            form.appendChild(div);
        }
        };


    function makeradarchart(){
        var datasets = [];

        var numberinput = parseInt(document.getElementById("numberinput").value, 10);
        for (var j = 0; j < numberinput; j++)
        {
            var label = document.getElementById("label" + j).value;
            var data = document.getElementById("data" + j).value.split(",");
            var colour = document.getElementById("colour" + j).value;
            var colour2 = document.getElementById("colour2" + j).value;
            var borderwidth = document.getElementById("borderwidth" + j).value;

            datasets.push({label:label, data:data, backgroundColor:colour, borderColor:colour2, borderWidth:borderwidth},);
        }


        var title = document.getElementById("title").value;
        var min = document.getElementById("min").value;
        var max = document.getElementById("max").value;
        var step = document.getElementById("step").value;
        var variables = document.getElementById("variables").value.split(",");

        //radar
        var ctxR = document.getElementById("radarchart").getContext('2d');
        var myRadarChart = new Chart(ctxR, {
            type: 'radar',
            data: {
                labels: variables,
                datasets: datasets
            },
            options:{
                title: {
                    display: true,
                    text: title
                },
                scale: {
                    ticks: {
                        min: parseFloat(min),
                        max: parseFloat(max),
                        stepSize: parseFloat(step)
                    },
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