$( document ).ready(function(){


  var button = document.getElementById("createscatterplot");

    button.onclick = function(){

        var scatterplot = document.getElementById("scatterplot");
        var input = document.getElementById("data").value.split(",");
        var xmin = document.getElementById("xmin").value;
        var xmax = document.getElementById("xmax").value;
        var ymin = document.getElementById("ymin").value;
        var ymax = document.getElementById("ymax").value;
        var xstep = document.getElementById("xstep").value;
        var ystep = document.getElementById("ystep").value;
        var bordercolour = document.getElementById("colour2").value;
        var borderwidth = document.getElementById("borderwidth").value;
        var colour = document.getElementById("colour").value;
        var title = document.getElementById("title").value;
        var xlabel = document.getElementById("xlabel").value;
        var ylabel = document.getElementById("ylabel").value;
        var radius = document.getElementById("radius").value;
        var name = document.getElementById("name").value.split(",");

        var x = 0;
        var y = 1;
        var i;
        var data = [];
        for (i=0; i < input.length/2; i++)
        {
            var xco = input[x];
            var yco = input[y];
            data.push({x:xco, y:yco},);
            x += 2;
            y += 2;
        }


        var ctxSc = document.getElementById('scatterplot').getContext('2d');
        var scatterData = {
            datasets: [{
                borderColor: bordercolour,
                backgroundColor: colour,
                borderWidth: borderwidth,
                pointRadius: parseInt(radius, 10),
                label: name,
                data: data
            }]
        };

        var myscatterplot = new Chart(ctxSc, {
            type: 'scatter',
            data: scatterData,
            options: {
            title: {
                display: true,
                text: title,
            },
            scales: {
                xAxes: [{
                    ticks: {
                        min: parseFloat(xmin),
                        max: parseFloat(xmax),
                        stepSize: parseFloat(xstep)
                        },
                    scaleLabel: {
                        display: true,
                        labelString: xlabel
                        }
                    }],
                yAxes: [{
                    ticks: {
                        min: parseFloat(ymin),
                        max: parseFloat(ymax),
                        stepSize: parseFloat(ystep)
                        },
                    scaleLabel: {
                        display: true,
                        labelString: ylabel
                        }
                    }],
                },
            }
        });
    // Background Colour
    backgroundcolour = document.getElementById("backgroundcolour").value;
    scatterplot.style.backgroundColor = backgroundcolour;
    };




   // download function
    $('#spdownload').click(function(){
        html2canvas(document.querySelector('#scatterplot')).then(function(canvas) {

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